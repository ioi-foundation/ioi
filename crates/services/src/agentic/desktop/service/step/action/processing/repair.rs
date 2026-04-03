use crate::agentic::desktop::execution::filesystem::resolve_tool_path;
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::lifecycle::load_worker_assignment;
use crate::agentic::desktop::service::step::action::execution_receipt_value;
use crate::agentic::desktop::service::step::anti_loop::{latest_failure_class, FailureClass};
use crate::agentic::desktop::service::step::worker::{
    filter_tools_for_worker_recovery, worker_recovery_failure_class,
};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::tools::discover_tools;
use crate::agentic::desktop::types::{AgentState, ToolCallStatus, WorkerAssignment};
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::{AgentTool, InferenceOptions, IntentScopeProfile, LlmToolDefinition};
use ioi_types::error::TransactionError;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

const INVALID_TOOL_REPAIR_TIMEOUT: Duration = Duration::from_secs(8);
const INVALID_TOOL_REPAIR_MODEL_ID: &str =
    "model_hash:0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) struct InvalidToolRepairAttempt {
    pub repaired_tool: Option<AgentTool>,
    pub verification_checks: Vec<String>,
}

enum DeterministicEditRepairValidation {
    Accepted(AgentTool),
    Rejected(String),
}

pub(crate) async fn attempt_refusal_repair(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    refusal_reason: &str,
) -> Result<InvalidToolRepairAttempt, TransactionError> {
    let mut verification_checks = Vec::new();
    let refusal_reason = refusal_reason.trim();
    if refusal_reason.is_empty() {
        verification_checks.push("refusal_repair_skipped=empty_reason".to_string());
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: None,
            verification_checks,
        });
    }

    let worker_assignment =
        load_worker_assignment(state, session_id).map_err(TransactionError::Invalid)?;
    if !invalid_tool_repair_supported(agent_state, worker_assignment.as_ref()) {
        verification_checks.push("refusal_repair_skipped=unsupported_scope".to_string());
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: None,
            verification_checks,
        });
    }

    let discovered_tools = discover_tools(
        state,
        service.memory_runtime.as_deref(),
        service.mcp.as_deref(),
        &agent_state.goal,
        service.fast_inference.clone(),
        agent_state.current_tier,
        "",
        agent_state.resolved_intent.as_ref(),
    )
    .await;
    let effective_failure = worker_recovery_failure_class(agent_state, worker_assignment.as_ref());
    let mut repair_tools = filter_tools_for_worker_recovery(
        &discovered_tools,
        agent_state,
        worker_assignment.as_ref(),
        effective_failure,
    );
    maybe_prefer_non_patch_edit_repair(
        agent_state,
        worker_assignment.as_ref(),
        &mut repair_tools,
        &mut verification_checks,
        "refusal_repair",
    );
    if repair_tools.is_empty() {
        verification_checks.push("refusal_repair_skipped=no_tools".to_string());
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: None,
            verification_checks,
        });
    }

    let allowed_tool_names = repair_tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<BTreeSet<_>>();
    let deterministic_allowed_tool_names = patch_build_verify_deterministic_allowed_tool_names(
        agent_state,
        worker_assignment.as_ref(),
        &allowed_tool_names,
        &mut verification_checks,
        "refusal_repair",
    );
    verification_checks.push("refusal_repair_attempted=true".to_string());
    verification_checks.push(format!(
        "refusal_repair_tool_count={}",
        allowed_tool_names.len()
    ));
    if let Some(workflow_id) = worker_assignment
        .as_ref()
        .and_then(|assignment| assignment.workflow_id.as_deref())
        .map(str::trim)
        .filter(|workflow_id| !workflow_id.is_empty())
    {
        verification_checks.push(format!("refusal_repair_workflow={workflow_id}"));
    }

    if let Some(repaired_tool) = synthesize_patch_build_verify_targeted_exec_refusal_repair(
        agent_state,
        worker_assignment.as_ref(),
        latest_failure_class(agent_state),
        effective_failure,
        &allowed_tool_names,
        refusal_reason,
        &mut verification_checks,
    ) {
        verification_checks.push("refusal_repair_succeeded=true".to_string());
        verification_checks.push(format!(
            "refusal_repair_tool={}",
            repaired_tool.name_string()
        ));
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: Some(repaired_tool),
            verification_checks,
        });
    }

    if let Some(outcome) = attempt_patch_build_verify_deterministic_edit_repair(
        agent_state,
        worker_assignment.as_ref(),
        &deterministic_allowed_tool_names,
        refusal_reason,
        &mut verification_checks,
    )
    .await?
    {
        if let DeterministicEditRepairValidation::Accepted(repaired_tool) = outcome {
            verification_checks.push("refusal_repair_succeeded=true".to_string());
            verification_checks.push(format!(
                "refusal_repair_tool={}",
                repaired_tool.name_string()
            ));
            verification_checks.push("refusal_repair_runtime=deterministic".to_string());
            return Ok(InvalidToolRepairAttempt {
                repaired_tool: Some(repaired_tool),
                verification_checks,
            });
        }
    }

    if let Some(repaired_tool) = attempt_patch_build_verify_refusal_edit_repair(
        service,
        agent_state,
        worker_assignment.as_ref(),
        session_id,
        refusal_reason,
        &repair_tools,
        &allowed_tool_names,
        effective_failure.map(|class| class.as_str()),
        &mut verification_checks,
    )
    .await?
    {
        verification_checks.push("refusal_repair_succeeded=true".to_string());
        verification_checks.push(format!(
            "refusal_repair_tool={}",
            repaired_tool.name_string()
        ));
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: Some(repaired_tool),
            verification_checks,
        });
    }

    verification_checks.push("refusal_repair_skipped=no_deterministic_followup".to_string());
    Ok(InvalidToolRepairAttempt {
        repaired_tool: None,
        verification_checks,
    })
}

pub(crate) fn attempt_patch_build_verify_runtime_patch_miss_repair(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    current_tool_name: &str,
    error_msg: Option<&str>,
    raw_tool_output: &str,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    if current_tool_name != "filesystem__patch" {
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
        .any(|tool| tool == "filesystem__write_file")
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

pub(crate) async fn attempt_invalid_tool_call_repair(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    raw_tool_output: &str,
    parse_error: &str,
) -> Result<InvalidToolRepairAttempt, TransactionError> {
    let mut verification_checks = Vec::new();
    let compact_output = raw_tool_output.trim();
    if compact_output.is_empty() {
        verification_checks.push("invalid_tool_call_repair_skipped=empty_output".to_string());
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: None,
            verification_checks,
        });
    }

    let worker_assignment =
        load_worker_assignment(state, session_id).map_err(TransactionError::Invalid)?;
    if !invalid_tool_repair_supported(agent_state, worker_assignment.as_ref()) {
        verification_checks.push("invalid_tool_call_repair_skipped=unsupported_scope".to_string());
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: None,
            verification_checks,
        });
    }

    let discovered_tools = discover_tools(
        state,
        service.memory_runtime.as_deref(),
        service.mcp.as_deref(),
        &agent_state.goal,
        service.fast_inference.clone(),
        agent_state.current_tier,
        "",
        agent_state.resolved_intent.as_ref(),
    )
    .await;
    let effective_failure = worker_recovery_failure_class(agent_state, worker_assignment.as_ref());
    let mut repair_tools = filter_tools_for_worker_recovery(
        &discovered_tools,
        agent_state,
        worker_assignment.as_ref(),
        effective_failure,
    );
    maybe_prefer_non_patch_edit_repair(
        agent_state,
        worker_assignment.as_ref(),
        &mut repair_tools,
        &mut verification_checks,
        "invalid_tool_call_repair",
    );
    if repair_tools.is_empty() {
        verification_checks.push("invalid_tool_call_repair_skipped=no_tools".to_string());
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: None,
            verification_checks,
        });
    }

    let allowed_tool_names = repair_tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<BTreeSet<_>>();
    let deterministic_allowed_tool_names = patch_build_verify_deterministic_allowed_tool_names(
        agent_state,
        worker_assignment.as_ref(),
        &allowed_tool_names,
        &mut verification_checks,
        "invalid_tool_call_repair",
    );
    verification_checks.push("invalid_tool_call_repair_attempted=true".to_string());
    verification_checks.push(format!(
        "invalid_tool_call_repair_tool_count={}",
        allowed_tool_names.len()
    ));
    if let Some(workflow_id) = worker_assignment
        .as_ref()
        .and_then(|assignment| assignment.workflow_id.as_deref())
        .map(str::trim)
        .filter(|workflow_id| !workflow_id.is_empty())
    {
        verification_checks.push(format!("invalid_tool_call_repair_workflow={workflow_id}"));
    }
    if let Some(repaired_tool) = synthesize_patch_build_verify_completion_after_success(
        agent_state,
        worker_assignment.as_ref(),
        &mut verification_checks,
    ) {
        verification_checks.push("invalid_tool_call_repair_succeeded=true".to_string());
        verification_checks.push(format!(
            "invalid_tool_call_repair_tool={}",
            repaired_tool.name_string()
        ));
        verification_checks.push("invalid_tool_call_repair_runtime=deterministic".to_string());
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: Some(repaired_tool),
            verification_checks,
        });
    }
    if let Some(repaired_tool) = synthesize_patch_build_verify_targeted_exec_repair(
        agent_state,
        worker_assignment.as_ref(),
        latest_failure_class(agent_state),
        effective_failure,
        &allowed_tool_names,
        compact_output,
        &mut verification_checks,
    ) {
        verification_checks.push("invalid_tool_call_repair_succeeded=true".to_string());
        verification_checks.push(format!(
            "invalid_tool_call_repair_tool={}",
            repaired_tool.name_string()
        ));
        verification_checks.push("invalid_tool_call_repair_runtime=deterministic".to_string());
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: Some(repaired_tool),
            verification_checks,
        });
    }
    if let Some(repaired_tool) = synthesize_patch_build_verify_refresh_read_repair(
        agent_state,
        worker_assignment.as_ref(),
        &allowed_tool_names,
        compact_output,
        &mut verification_checks,
    ) {
        verification_checks.push("invalid_tool_call_repair_succeeded=true".to_string());
        verification_checks.push(format!(
            "invalid_tool_call_repair_tool={}",
            repaired_tool.name_string()
        ));
        verification_checks.push("invalid_tool_call_repair_runtime=deterministic".to_string());
        return Ok(InvalidToolRepairAttempt {
            repaired_tool: Some(repaired_tool),
            verification_checks,
        });
    }

    let prefer_runtime_edit_repair = should_prefer_runtime_patch_build_verify_edit_repair(
        agent_state,
        worker_assignment.as_ref(),
    );
    let mut deterministic_rejection = None;
    if prefer_runtime_edit_repair {
        if let Some(outcome) = attempt_patch_build_verify_deterministic_edit_repair(
            agent_state,
            worker_assignment.as_ref(),
            &deterministic_allowed_tool_names,
            compact_output,
            &mut verification_checks,
        )
        .await?
        {
            match outcome {
                DeterministicEditRepairValidation::Accepted(repaired_tool) => {
                    verification_checks.push("invalid_tool_call_repair_succeeded=true".to_string());
                    verification_checks.push(format!(
                        "invalid_tool_call_repair_tool={}",
                        repaired_tool.name_string()
                    ));
                    verification_checks
                        .push("invalid_tool_call_repair_runtime=deterministic".to_string());
                    return Ok(InvalidToolRepairAttempt {
                        repaired_tool: Some(repaired_tool),
                        verification_checks,
                    });
                }
                DeterministicEditRepairValidation::Rejected(failure_summary) => {
                    deterministic_rejection = Some(failure_summary);
                }
            }
        }
    }

    let mut last_failure = None;
    if prefer_runtime_edit_repair {
        let runtime_attempt = attempt_invalid_tool_call_runtime_repair(
            service,
            agent_state,
            worker_assignment.as_ref(),
            session_id,
            &repair_tools,
            &allowed_tool_names,
            effective_failure.map(|class| class.as_str()),
            parse_error,
            compact_output,
            deterministic_rejection.as_deref(),
            &mut verification_checks,
        )
        .await?;
        if let Some(repaired_tool) = runtime_attempt.repaired_tool {
            return Ok(InvalidToolRepairAttempt {
                repaired_tool: Some(repaired_tool),
                verification_checks,
            });
        }
        last_failure = runtime_attempt.failure_summary;
    }

    if !prefer_runtime_edit_repair {
        if let Some(outcome) = attempt_patch_build_verify_deterministic_edit_repair(
            agent_state,
            worker_assignment.as_ref(),
            &deterministic_allowed_tool_names,
            compact_output,
            &mut verification_checks,
        )
        .await?
        {
            if let DeterministicEditRepairValidation::Accepted(repaired_tool) = outcome {
                verification_checks.push("invalid_tool_call_repair_succeeded=true".to_string());
                verification_checks.push(format!(
                    "invalid_tool_call_repair_tool={}",
                    repaired_tool.name_string()
                ));
                verification_checks
                    .push("invalid_tool_call_repair_runtime=deterministic".to_string());
                return Ok(InvalidToolRepairAttempt {
                    repaired_tool: Some(repaired_tool),
                    verification_checks,
                });
            }
        }

        let runtime_attempt = attempt_invalid_tool_call_runtime_repair(
            service,
            agent_state,
            worker_assignment.as_ref(),
            session_id,
            &repair_tools,
            &allowed_tool_names,
            effective_failure.map(|class| class.as_str()),
            parse_error,
            compact_output,
            None,
            &mut verification_checks,
        )
        .await?;
        if let Some(repaired_tool) = runtime_attempt.repaired_tool {
            return Ok(InvalidToolRepairAttempt {
                repaired_tool: Some(repaired_tool),
                verification_checks,
            });
        }
        last_failure = runtime_attempt.failure_summary.or(last_failure);
    }

    if let Some(failure_summary) = last_failure {
        verification_checks.push(format!(
            "invalid_tool_call_repair_inference_error={}",
            sanitize_check_value(&failure_summary)
        ));
    }
    Ok(InvalidToolRepairAttempt {
        repaired_tool: None,
        verification_checks,
    })
}

struct RepairRuntimeAttempt {
    repaired_tool: Option<AgentTool>,
    failure_summary: Option<String>,
}

async fn attempt_invalid_tool_call_runtime_repair(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    session_id: [u8; 32],
    repair_tools: &[LlmToolDefinition],
    allowed_tool_names: &BTreeSet<String>,
    effective_failure: Option<&str>,
    parse_error: &str,
    raw_tool_output: &str,
    initial_rejection_summary: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> Result<RepairRuntimeAttempt, TransactionError> {
    if let Some(rejection_summary) = initial_rejection_summary {
        verification_checks.push(format!(
            "invalid_tool_call_repair_runtime_fast_retry_after_deterministic_rejection={}",
            sanitize_check_value(rejection_summary)
        ));
        let fast_attempt = attempt_patch_build_verify_constrained_runtime_repair(
            service,
            service.fast_inference.clone(),
            "fast",
            agent_state,
            worker_assignment,
            session_id,
            effective_failure,
            parse_error,
            raw_tool_output,
            rejection_summary,
            repair_tools,
            verification_checks,
        )
        .await?;
        let fast_failure = fast_attempt.failure_summary.clone();
        let mut last_failure = fast_failure.clone();
        if let Some(repaired_tool) = fast_attempt.repaired_tool {
            return Ok(RepairRuntimeAttempt {
                repaired_tool: Some(repaired_tool),
                failure_summary: None,
            });
        }
        if let Some(failure_summary) = fast_failure.as_deref() {
            verification_checks.push(format!(
                "invalid_tool_call_repair_runtime_fast_retry_after_failure={}",
                sanitize_check_value(failure_summary)
            ));
            let retry_attempt = attempt_patch_build_verify_constrained_runtime_repair(
                service,
                service.fast_inference.clone(),
                "fast_retry",
                agent_state,
                worker_assignment,
                session_id,
                effective_failure,
                parse_error,
                raw_tool_output,
                failure_summary,
                repair_tools,
                verification_checks,
            )
            .await?;
            if let Some(repaired_tool) = retry_attempt.repaired_tool {
                return Ok(RepairRuntimeAttempt {
                    repaired_tool: Some(repaired_tool),
                    failure_summary: None,
                });
            }
            last_failure = retry_attempt.failure_summary.or(last_failure);
        }

        if !Arc::ptr_eq(&service.fast_inference, &service.reasoning_inference) {
            verification_checks.push("invalid_tool_call_repair_runtime_fallback=true".to_string());
            verification_checks.push(format!(
                "invalid_tool_call_repair_runtime_reasoning_retry_after_deterministic_rejection={}",
                sanitize_check_value(rejection_summary)
            ));
            let reasoning_attempt = attempt_patch_build_verify_constrained_runtime_repair(
                service,
                service.reasoning_inference.clone(),
                "reasoning",
                agent_state,
                worker_assignment,
                session_id,
                effective_failure,
                parse_error,
                raw_tool_output,
                rejection_summary,
                repair_tools,
                verification_checks,
            )
            .await?;
            let reasoning_failure = reasoning_attempt.failure_summary.clone();
            if let Some(repaired_tool) = reasoning_attempt.repaired_tool {
                return Ok(RepairRuntimeAttempt {
                    repaired_tool: Some(repaired_tool),
                    failure_summary: None,
                });
            }
            if let Some(failure_summary) = reasoning_failure.as_deref() {
                verification_checks.push(format!(
                    "invalid_tool_call_repair_runtime_reasoning_retry_after_failure={}",
                    sanitize_check_value(failure_summary)
                ));
                let retry_attempt = attempt_patch_build_verify_constrained_runtime_repair(
                    service,
                    service.reasoning_inference.clone(),
                    "reasoning_retry",
                    agent_state,
                    worker_assignment,
                    session_id,
                    effective_failure,
                    parse_error,
                    raw_tool_output,
                    failure_summary,
                    repair_tools,
                    verification_checks,
                )
                .await?;
                if let Some(repaired_tool) = retry_attempt.repaired_tool {
                    return Ok(RepairRuntimeAttempt {
                        repaired_tool: Some(repaired_tool),
                        failure_summary: None,
                    });
                }
                last_failure = retry_attempt.failure_summary.or(last_failure);
            }
        }

        return Ok(RepairRuntimeAttempt {
            repaired_tool: None,
            failure_summary: last_failure,
        });
    }

    let prompt = build_invalid_tool_repair_prompt(
        agent_state,
        worker_assignment,
        allowed_tool_names,
        effective_failure,
        parse_error,
        raw_tool_output,
    );
    let messages = json!([
        { "role": "system", "content": prompt },
        {
            "role": "user",
            "content": "Emit exactly one valid JSON tool call now."
        }
    ]);
    let input = serde_json::to_vec(&messages)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let fast_attempt = run_invalid_tool_call_repair_inference(
        service,
        service.fast_inference.clone(),
        "fast",
        agent_state,
        worker_assignment,
        session_id,
        &input,
        repair_tools,
        allowed_tool_names,
        verification_checks,
    )
    .await?;
    let fast_failure = fast_attempt.failure_summary.clone();
    let mut last_failure = fast_failure.clone();
    if let Some(repaired_tool) = fast_attempt.repaired_tool {
        let repaired_tool = upconvert_patch_build_verify_runtime_line_edit_repair(
            agent_state,
            worker_assignment,
            raw_tool_output,
            repaired_tool,
            verification_checks,
        );
        if let Some(failure_summary) = validate_patch_build_verify_runtime_edit_repair(
            agent_state,
            worker_assignment,
            raw_tool_output,
            &repaired_tool,
            verification_checks,
            "invalid_tool_call_repair",
            "fast",
        )
        .await?
        {
            if let retry_attempt @ RepairRuntimeAttempt {
                repaired_tool: Some(_),
                ..
            } = attempt_patch_build_verify_constrained_runtime_repair(
                service,
                service.fast_inference.clone(),
                "fast_retry",
                agent_state,
                worker_assignment,
                session_id,
                effective_failure,
                parse_error,
                raw_tool_output,
                &failure_summary,
                repair_tools,
                verification_checks,
            )
            .await?
            {
                return Ok(retry_attempt);
            }
            last_failure = Some(failure_summary);
        } else {
            verification_checks.push("invalid_tool_call_repair_succeeded=true".to_string());
            verification_checks.push(format!(
                "invalid_tool_call_repair_tool={}",
                repaired_tool.name_string()
            ));
            verification_checks.push("invalid_tool_call_repair_runtime=fast".to_string());
            return Ok(RepairRuntimeAttempt {
                repaired_tool: Some(repaired_tool),
                failure_summary: None,
            });
        }
    } else if let Some(failure_summary) = fast_failure.as_deref() {
        verification_checks.push(format!(
            "invalid_tool_call_repair_runtime_fast_retry_after_failure={}",
            sanitize_check_value(failure_summary)
        ));
        let retry_attempt = attempt_patch_build_verify_constrained_runtime_repair(
            service,
            service.fast_inference.clone(),
            "fast_retry",
            agent_state,
            worker_assignment,
            session_id,
            effective_failure,
            parse_error,
            raw_tool_output,
            failure_summary,
            repair_tools,
            verification_checks,
        )
        .await?;
        if let Some(repaired_tool) = retry_attempt.repaired_tool {
            return Ok(RepairRuntimeAttempt {
                repaired_tool: Some(repaired_tool),
                failure_summary: None,
            });
        }
        last_failure = retry_attempt.failure_summary.or(last_failure);
    }

    if !Arc::ptr_eq(&service.fast_inference, &service.reasoning_inference) {
        verification_checks.push("invalid_tool_call_repair_runtime_fallback=true".to_string());
        let reasoning_attempt = run_invalid_tool_call_repair_inference(
            service,
            service.reasoning_inference.clone(),
            "reasoning",
            agent_state,
            worker_assignment,
            session_id,
            &input,
            repair_tools,
            allowed_tool_names,
            verification_checks,
        )
        .await?;
        let reasoning_failure = reasoning_attempt.failure_summary.clone();
        if let Some(repaired_tool) = reasoning_attempt.repaired_tool {
            let repaired_tool = upconvert_patch_build_verify_runtime_line_edit_repair(
                agent_state,
                worker_assignment,
                raw_tool_output,
                repaired_tool,
                verification_checks,
            );
            if let Some(failure_summary) = validate_patch_build_verify_runtime_edit_repair(
                agent_state,
                worker_assignment,
                raw_tool_output,
                &repaired_tool,
                verification_checks,
                "invalid_tool_call_repair",
                "reasoning",
            )
            .await?
            {
                if let retry_attempt @ RepairRuntimeAttempt {
                    repaired_tool: Some(_),
                    ..
                } = attempt_patch_build_verify_constrained_runtime_repair(
                    service,
                    service.reasoning_inference.clone(),
                    "reasoning_retry",
                    agent_state,
                    worker_assignment,
                    session_id,
                    effective_failure,
                    parse_error,
                    raw_tool_output,
                    &failure_summary,
                    repair_tools,
                    verification_checks,
                )
                .await?
                {
                    return Ok(retry_attempt);
                }
                last_failure = Some(failure_summary);
            } else {
                verification_checks.push("invalid_tool_call_repair_succeeded=true".to_string());
                verification_checks.push(format!(
                    "invalid_tool_call_repair_tool={}",
                    repaired_tool.name_string()
                ));
                verification_checks.push("invalid_tool_call_repair_runtime=reasoning".to_string());
                return Ok(RepairRuntimeAttempt {
                    repaired_tool: Some(repaired_tool),
                    failure_summary: None,
                });
            }
        } else if let Some(failure_summary) = reasoning_failure.as_deref() {
            verification_checks.push(format!(
                "invalid_tool_call_repair_runtime_reasoning_retry_after_failure={}",
                sanitize_check_value(failure_summary)
            ));
            let retry_attempt = attempt_patch_build_verify_constrained_runtime_repair(
                service,
                service.reasoning_inference.clone(),
                "reasoning_retry",
                agent_state,
                worker_assignment,
                session_id,
                effective_failure,
                parse_error,
                raw_tool_output,
                failure_summary,
                repair_tools,
                verification_checks,
            )
            .await?;
            if let Some(repaired_tool) = retry_attempt.repaired_tool {
                return Ok(RepairRuntimeAttempt {
                    repaired_tool: Some(repaired_tool),
                    failure_summary: None,
                });
            }
            last_failure = retry_attempt.failure_summary.or(last_failure);
        }
        last_failure = reasoning_failure.or(last_failure);
    }

    Ok(RepairRuntimeAttempt {
        repaired_tool: None,
        failure_summary: last_failure,
    })
}

async fn attempt_patch_build_verify_constrained_runtime_repair(
    service: &DesktopAgentService,
    runtime: Arc<dyn InferenceRuntime>,
    runtime_label: &str,
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    session_id: [u8; 32],
    effective_failure: Option<&str>,
    parse_error: &str,
    raw_tool_output: &str,
    rejection_summary: &str,
    repair_tools: &[LlmToolDefinition],
    verification_checks: &mut Vec<String>,
) -> Result<RepairRuntimeAttempt, TransactionError> {
    if !patch_build_verify_should_retry_constrained_runtime_repair(
        agent_state,
        worker_assignment,
        rejection_summary,
    ) {
        return Ok(RepairRuntimeAttempt {
            repaired_tool: None,
            failure_summary: Some(rejection_summary.to_string()),
        });
    }

    let constrained_tools = patch_build_verify_edit_only_repair_tools(repair_tools);
    if constrained_tools.is_empty() {
        verification_checks.push(format!(
            "invalid_tool_call_repair_runtime_{}_skipped=no_edit_tools",
            runtime_label
        ));
        return Ok(RepairRuntimeAttempt {
            repaired_tool: None,
            failure_summary: Some(rejection_summary.to_string()),
        });
    }

    let constrained_allowed_tool_names = constrained_tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<BTreeSet<_>>();
    let prompt = build_invalid_tool_repair_retry_prompt(
        agent_state,
        worker_assignment,
        &constrained_allowed_tool_names,
        effective_failure,
        parse_error,
        raw_tool_output,
        rejection_summary,
    );
    let messages = json!([
        { "role": "system", "content": prompt },
        {
            "role": "user",
            "content": "Emit exactly one valid JSON tool call now."
        }
    ]);
    let input = serde_json::to_vec(&messages)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let retry_attempt = run_invalid_tool_call_repair_inference(
        service,
        runtime,
        runtime_label,
        agent_state,
        worker_assignment,
        session_id,
        &input,
        &constrained_tools,
        &constrained_allowed_tool_names,
        verification_checks,
    )
    .await?;
    let Some(repaired_tool) = retry_attempt.repaired_tool else {
        return Ok(RepairRuntimeAttempt {
            repaired_tool: None,
            failure_summary: retry_attempt
                .failure_summary
                .or_else(|| Some(rejection_summary.to_string())),
        });
    };

    let repaired_tool = upconvert_patch_build_verify_runtime_line_edit_repair(
        agent_state,
        worker_assignment,
        raw_tool_output,
        repaired_tool,
        verification_checks,
    );
    if let Some(failure_summary) = validate_patch_build_verify_runtime_edit_repair(
        agent_state,
        worker_assignment,
        raw_tool_output,
        &repaired_tool,
        verification_checks,
        "invalid_tool_call_repair",
        runtime_label,
    )
    .await?
    {
        return Ok(RepairRuntimeAttempt {
            repaired_tool: None,
            failure_summary: Some(failure_summary),
        });
    }

    verification_checks.push("invalid_tool_call_repair_succeeded=true".to_string());
    verification_checks.push(format!(
        "invalid_tool_call_repair_tool={}",
        repaired_tool.name_string()
    ));
    verification_checks.push(format!("invalid_tool_call_repair_runtime={runtime_label}"));
    Ok(RepairRuntimeAttempt {
        repaired_tool: Some(repaired_tool),
        failure_summary: None,
    })
}

async fn attempt_patch_build_verify_refusal_edit_repair(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    session_id: [u8; 32],
    refusal_reason: &str,
    repair_tools: &[LlmToolDefinition],
    allowed_tool_names: &BTreeSet<String>,
    effective_failure: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> Result<Option<AgentTool>, TransactionError> {
    let Some(assignment) = worker_assignment else {
        return Ok(None);
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return Ok(None);
    }
    if latest_command_failure_summary(agent_state).is_none() {
        return Ok(None);
    }
    if !allowed_tool_names.iter().any(|tool_name| {
        matches!(
            tool_name.as_str(),
            "filesystem__patch" | "filesystem__edit_line" | "filesystem__write_file"
        )
    }) {
        return Ok(None);
    }

    let prompt = build_refusal_repair_prompt(
        agent_state,
        Some(assignment),
        allowed_tool_names,
        effective_failure,
        refusal_reason,
    );
    let messages = json!([
        { "role": "system", "content": prompt },
        {
            "role": "user",
            "content": "Emit exactly one valid JSON tool call now."
        }
    ]);
    let input = serde_json::to_vec(&messages)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;

    let fast_attempt = run_refusal_repair_inference(
        service,
        service.fast_inference.clone(),
        "fast",
        agent_state,
        worker_assignment,
        session_id,
        &input,
        repair_tools,
        allowed_tool_names,
        verification_checks,
    )
    .await?;
    if let Some(repaired_tool) = fast_attempt.repaired_tool {
        let repaired_tool = upconvert_patch_build_verify_runtime_line_edit_repair(
            agent_state,
            worker_assignment,
            refusal_reason,
            repaired_tool,
            verification_checks,
        );
        if validate_patch_build_verify_runtime_edit_repair(
            agent_state,
            worker_assignment,
            refusal_reason,
            &repaired_tool,
            verification_checks,
            "refusal_repair",
            "fast",
        )
        .await?
        .is_none()
        {
            verification_checks.push("refusal_repair_runtime=fast".to_string());
            return Ok(Some(repaired_tool));
        }
    }

    let mut last_failure = fast_attempt.failure_summary;
    if !Arc::ptr_eq(&service.fast_inference, &service.reasoning_inference) {
        verification_checks.push("refusal_repair_runtime_fallback=true".to_string());
        let reasoning_attempt = run_refusal_repair_inference(
            service,
            service.reasoning_inference.clone(),
            "reasoning",
            agent_state,
            worker_assignment,
            session_id,
            &input,
            repair_tools,
            allowed_tool_names,
            verification_checks,
        )
        .await?;
        if let Some(repaired_tool) = reasoning_attempt.repaired_tool {
            let repaired_tool = upconvert_patch_build_verify_runtime_line_edit_repair(
                agent_state,
                worker_assignment,
                refusal_reason,
                repaired_tool,
                verification_checks,
            );
            if validate_patch_build_verify_runtime_edit_repair(
                agent_state,
                worker_assignment,
                refusal_reason,
                &repaired_tool,
                verification_checks,
                "refusal_repair",
                "reasoning",
            )
            .await?
            .is_none()
            {
                verification_checks.push("refusal_repair_runtime=reasoning".to_string());
                return Ok(Some(repaired_tool));
            }
        }
        last_failure = reasoning_attempt.failure_summary.or(last_failure);
    }

    if let Some(failure_summary) = last_failure {
        verification_checks.push(format!(
            "refusal_repair_inference_error={}",
            sanitize_check_value(&failure_summary)
        ));
    }

    Ok(None)
}

async fn run_invalid_tool_call_repair_inference(
    service: &DesktopAgentService,
    runtime: Arc<dyn InferenceRuntime>,
    runtime_label: &str,
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    session_id: [u8; 32],
    input: &[u8],
    repair_tools: &[LlmToolDefinition],
    allowed_tool_names: &BTreeSet<String>,
    verification_checks: &mut Vec<String>,
) -> Result<RepairRuntimeAttempt, TransactionError> {
    verification_checks.push(format!(
        "invalid_tool_call_repair_runtime_attempt={runtime_label}"
    ));
    let options = InferenceOptions {
        temperature: 0.0,
        json_mode: true,
        max_tokens: 256,
        tools: repair_tools.to_vec(),
        ..Default::default()
    };
    let inference_input = service
        .prepare_cloud_inference_input(
            Some(session_id),
            "desktop_agent",
            INVALID_TOOL_REPAIR_MODEL_ID,
            input,
        )
        .await?;
    let output_bytes = match tokio::time::timeout(
        INVALID_TOOL_REPAIR_TIMEOUT,
        runtime.execute_inference([0u8; 32], &inference_input, options),
    )
    .await
    {
        Err(_) => {
            verification_checks.push(format!(
                "invalid_tool_call_repair_runtime_{}_timeout=true",
                runtime_label
            ));
            return Ok(RepairRuntimeAttempt {
                repaired_tool: None,
                failure_summary: Some(format!("{runtime_label}:timeout")),
            });
        }
        Ok(Err(error)) => {
            verification_checks.push(format!(
                "invalid_tool_call_repair_runtime_{}_error={}",
                runtime_label,
                sanitize_check_value(&error.to_string())
            ));
            return Ok(RepairRuntimeAttempt {
                repaired_tool: None,
                failure_summary: Some(format!("{runtime_label}:{}", error)),
            });
        }
        Ok(Ok(bytes)) => bytes,
    };

    let repaired_output = String::from_utf8_lossy(&output_bytes).to_string();
    if repaired_output.trim().is_empty() {
        verification_checks.push(format!(
            "invalid_tool_call_repair_runtime_{}_empty_output=true",
            runtime_label
        ));
        return Ok(RepairRuntimeAttempt {
            repaired_tool: None,
            failure_summary: Some(format!("{runtime_label}:empty_output")),
        });
    }

    let repaired_tool = match middleware::normalize_tool_call(&repaired_output) {
        Ok(tool) => tool,
        Err(error) => {
            verification_checks.push(format!(
                "invalid_tool_call_repair_runtime_{}_normalize_error={}",
                runtime_label,
                sanitize_check_value(&error.to_string())
            ));
            return Ok(RepairRuntimeAttempt {
                repaired_tool: None,
                failure_summary: Some(format!("{runtime_label}:normalize:{}", error)),
            });
        }
    };
    let repaired_tool = maybe_salvage_disallowed_patch_build_verify_runtime_edit(
        agent_state,
        worker_assignment,
        &repaired_output,
        &repaired_tool,
        allowed_tool_names,
        verification_checks,
        "invalid_tool_call_repair",
    )
    .unwrap_or(repaired_tool);
    let repaired_tool_name = repaired_tool.name_string();
    if !allowed_tool_names.contains(&repaired_tool_name) {
        verification_checks.push(format!(
            "invalid_tool_call_repair_runtime_{}_disallowed_tool={}",
            runtime_label,
            sanitize_check_value(&repaired_tool_name)
        ));
        return Ok(RepairRuntimeAttempt {
            repaired_tool: None,
            failure_summary: Some(format!(
                "{runtime_label}:disallowed_tool:{}",
                repaired_tool_name
            )),
        });
    }

    Ok(RepairRuntimeAttempt {
        repaired_tool: Some(repaired_tool),
        failure_summary: None,
    })
}

async fn run_refusal_repair_inference(
    service: &DesktopAgentService,
    runtime: Arc<dyn InferenceRuntime>,
    runtime_label: &str,
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    session_id: [u8; 32],
    input: &[u8],
    repair_tools: &[LlmToolDefinition],
    allowed_tool_names: &BTreeSet<String>,
    verification_checks: &mut Vec<String>,
) -> Result<RepairRuntimeAttempt, TransactionError> {
    verification_checks.push(format!("refusal_repair_runtime_attempt={runtime_label}"));
    let options = InferenceOptions {
        temperature: 0.0,
        json_mode: true,
        max_tokens: 256,
        tools: repair_tools.to_vec(),
        ..Default::default()
    };
    let inference_input = service
        .prepare_cloud_inference_input(
            Some(session_id),
            "desktop_agent",
            INVALID_TOOL_REPAIR_MODEL_ID,
            input,
        )
        .await?;
    let output_bytes = match tokio::time::timeout(
        INVALID_TOOL_REPAIR_TIMEOUT,
        runtime.execute_inference([0u8; 32], &inference_input, options),
    )
    .await
    {
        Err(_) => {
            verification_checks.push(format!(
                "refusal_repair_runtime_{}_timeout=true",
                runtime_label
            ));
            return Ok(RepairRuntimeAttempt {
                repaired_tool: None,
                failure_summary: Some(format!("{runtime_label}:timeout")),
            });
        }
        Ok(Err(error)) => {
            verification_checks.push(format!(
                "refusal_repair_runtime_{}_error={}",
                runtime_label,
                sanitize_check_value(&error.to_string())
            ));
            return Ok(RepairRuntimeAttempt {
                repaired_tool: None,
                failure_summary: Some(format!("{runtime_label}:{}", error)),
            });
        }
        Ok(Ok(bytes)) => bytes,
    };

    let repaired_output = String::from_utf8_lossy(&output_bytes).to_string();
    if repaired_output.trim().is_empty() {
        verification_checks.push(format!(
            "refusal_repair_runtime_{}_empty_output=true",
            runtime_label
        ));
        return Ok(RepairRuntimeAttempt {
            repaired_tool: None,
            failure_summary: Some(format!("{runtime_label}:empty_output")),
        });
    }

    let repaired_tool = match middleware::normalize_tool_call(&repaired_output) {
        Ok(tool) => tool,
        Err(error) => {
            verification_checks.push(format!(
                "refusal_repair_runtime_{}_parse_error={}",
                runtime_label,
                sanitize_check_value(&error.to_string())
            ));
            return Ok(RepairRuntimeAttempt {
                repaired_tool: None,
                failure_summary: Some(format!("{runtime_label}:{}", error)),
            });
        }
    };

    let repaired_tool = maybe_salvage_disallowed_patch_build_verify_runtime_edit(
        agent_state,
        worker_assignment,
        &repaired_output,
        &repaired_tool,
        allowed_tool_names,
        verification_checks,
        "refusal_repair",
    )
    .unwrap_or(repaired_tool);

    if !allowed_tool_names.contains(&repaired_tool.name_string()) {
        verification_checks.push(format!(
            "refusal_repair_runtime_{}_disallowed_tool={}",
            runtime_label,
            sanitize_check_value(&repaired_tool.name_string())
        ));
        return Ok(RepairRuntimeAttempt {
            repaired_tool: None,
            failure_summary: Some(format!(
                "{runtime_label}:disallowed_tool:{}",
                repaired_tool.name_string()
            )),
        });
    }

    Ok(RepairRuntimeAttempt {
        repaired_tool: Some(repaired_tool),
        failure_summary: None,
    })
}

fn invalid_tool_repair_supported(
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

async fn validate_patch_build_verify_runtime_edit_repair(
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

fn patch_build_verify_runtime_edit_validation_projection(
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

async fn validate_patch_build_verify_deterministic_edit_repair(
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

async fn attempt_patch_build_verify_deterministic_edit_repair(
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

fn validate_patch_build_verify_runtime_goal_constraints(
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

fn validate_patch_build_verify_runtime_repair_boundary(
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

fn patch_build_verify_should_retry_constrained_runtime_repair(
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

fn patch_build_verify_goal_requires_leading_path_preservation(goal_lower: &str) -> bool {
    goal_lower.contains("preserve a leading `./` or `/`")
        || goal_lower.contains("preserves a leading `./` or `/`")
        || goal_lower.contains("preserve a leading ./ or /")
        || goal_lower.contains("preserves a leading ./ or /")
}

fn patch_build_verify_goal_requires_duplicate_separator_collapse(goal_lower: &str) -> bool {
    goal_lower.contains("collapse duplicate separators")
        || goal_lower.contains("collapses duplicate separators")
        || goal_lower.contains("collapse duplicate separator")
}

fn patch_build_verify_goal_requires_forward_slash_normalization(goal_lower: &str) -> bool {
    goal_lower.contains("convert backslashes to forward slashes")
        || goal_lower.contains("converts backslashes to forward slashes")
        || goal_lower.contains("convert backslash to forward slash")
        || goal_lower.contains("converts backslash to forward slash")
}

fn patch_build_verify_goal_requires_path_parity(goal_lower: &str) -> bool {
    patch_build_verify_goal_requires_leading_path_preservation(goal_lower)
        && patch_build_verify_goal_requires_duplicate_separator_collapse(goal_lower)
        && patch_build_verify_goal_requires_forward_slash_normalization(goal_lower)
}

fn patch_build_verify_current_block_needs_path_parity_repair(current_block: &str) -> bool {
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

fn patch_build_verify_runtime_edit_strips_required_prefix(content: &str) -> bool {
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

fn patch_build_verify_runtime_edit_uses_single_pass_separator_collapse(content: &str) -> bool {
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

fn patch_build_verify_runtime_edit_reverses_separator_direction(content: &str) -> bool {
    let normalized = content
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .replace('"', "'");
    normalized.contains(".replace('/','\\')") || normalized.contains(".replace('/','\\\\')")
}

fn patch_build_verify_runtime_candidate_failure_summary(
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

fn patch_build_verify_runtime_line_edit_requires_full_write(content: &str) -> bool {
    let normalized = normalize_code_block_content(content);
    normalized
        .lines()
        .filter(|line| !line.trim().is_empty())
        .nth(1)
        .is_some()
        || matches_python_function_signature(normalized.trim_start())
}

fn patch_build_verify_preview_line_edit(
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

fn patch_build_verify_runtime_line_edit_within_current_file(
    current_content: &str,
    line_number: u32,
) -> bool {
    let line_count = current_content.lines().count();
    line_number > 0 && (line_number as usize) <= line_count
}

fn patch_build_verify_edit_only_repair_tools(
    repair_tools: &[LlmToolDefinition],
) -> Vec<LlmToolDefinition> {
    repair_tools
        .iter()
        .filter(|tool| {
            matches!(
                tool.name.as_str(),
                "filesystem__patch" | "filesystem__edit_line" | "filesystem__write_file"
            )
        })
        .cloned()
        .collect()
}

fn patch_build_verify_runtime_edit_targets_expected_path(
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

fn patch_build_verify_runtime_repair_preserves_python_signature(
    current_content: &str,
    candidate_content: &str,
) -> bool {
    let Some(current_signature) = single_python_function_signature(current_content) else {
        return true;
    };
    let Some(candidate_signature) = single_python_function_signature(candidate_content) else {
        return false;
    };

    current_signature == candidate_signature
}

fn single_python_function_signature(content: &str) -> Option<String> {
    let signatures = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            matches_python_function_signature(trimmed).then_some(trimmed.trim_end().to_string())
        })
        .collect::<Vec<_>>();
    if signatures.len() == 1 {
        signatures.into_iter().next()
    } else {
        None
    }
}

async fn validate_python_module_syntax(content: &str) -> Result<Option<String>, TransactionError> {
    let staged_file = tempfile::Builder::new()
        .suffix(".py")
        .tempfile()
        .map_err(|error| {
            TransactionError::Invalid(format!(
                "failed to create temporary python syntax check file: {error}"
            ))
        })?;
    fs::write(staged_file.path(), content).map_err(|error| {
        TransactionError::Invalid(format!(
            "failed to stage temporary python syntax check file: {error}"
        ))
    })?;

    let output = match Command::new("python3")
        .arg("-m")
        .arg("py_compile")
        .arg(staged_file.path())
        .output()
        .await
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(TransactionError::Invalid(format!(
                "failed to run python syntax check: {error}"
            )))
        }
    };
    if output.status.success() {
        return Ok(None);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    Ok(Some(truncate_for_prompt(&detail, 160)))
}

fn synthesize_patch_build_verify_targeted_exec_repair(
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

fn synthesize_patch_build_verify_targeted_exec_refusal_repair(
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

fn synthesize_patch_build_verify_targeted_exec_bootstrap(
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

fn synthesize_patch_build_verify_targeted_exec_followup(
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

fn synthesize_patch_build_verify_completion_after_success(
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

fn reason_is_empty_content_refusal(reason: &str) -> bool {
    let normalized = reason.trim().to_ascii_lowercase();
    normalized.contains("empty content") || normalized.contains("reason: stop")
}

fn patch_build_verify_should_prefer_non_patch_edit_repair(
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
}

fn should_prefer_runtime_patch_build_verify_edit_repair(
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

fn maybe_prefer_non_patch_edit_repair(
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

fn patch_build_verify_deterministic_allowed_tool_names(
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

fn synthesize_patch_build_verify_refresh_read_repair(
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

fn synthesize_patch_build_verify_code_block_edit_repair(
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

fn synthesize_patch_build_verify_inline_code_edit_repair(
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

fn synthesize_patch_build_verify_goal_constrained_snapshot_repair(
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

fn upconvert_patch_build_verify_runtime_line_edit_repair(
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

fn patch_build_verify_repair_source_from_raw_tool_output(raw_tool_output: &str) -> Option<String> {
    let tool = middleware::normalize_tool_call(raw_tool_output).ok()?;
    match tool {
        AgentTool::FsPatch { replace, .. } => Some(replace),
        AgentTool::FsWrite { content, .. } => Some(content),
        _ => None,
    }
}

fn patch_build_verify_edit_tool_path(tool: &AgentTool) -> Option<&str> {
    match tool {
        AgentTool::FsPatch { path, .. } | AgentTool::FsWrite { path, .. } => Some(path.as_str()),
        _ => None,
    }
}

fn patch_build_verify_goal_constrained_snapshot_content(
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

fn patch_build_verify_goal_constrained_snapshot_rewrite(
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

fn patch_build_verify_updated_content_from_repair_source(
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

fn maybe_salvage_disallowed_patch_build_verify_runtime_edit(
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

fn build_invalid_tool_repair_prompt(
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
7. Prefer `filesystem__patch`, `filesystem__edit_line`, or `filesystem__write_file` when the malformed response already contains the intended code change.\n\
8. Use `sys__exec_session` only after the edit is ready for the focused verification command.\n\
9. If the focused verification command already ran and failed, produce an edit tool call next instead of rerunning tests.\n\
10. If you use `filesystem__write_file` for a code edit, omit `line_number` and provide the full updated file contents grounded in the current file snapshot.\n",
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

fn build_invalid_tool_repair_retry_prompt(
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
4. If you use `filesystem__write_file`, provide the full updated file contents.\n",
    );
    prompt
}

fn build_refusal_repair_prompt(
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
6. After a failing focused verifier result, produce `filesystem__patch`, `filesystem__edit_line`, or `filesystem__write_file` next.\n\
7. Do not emit `sys__exec_session` again until a workspace edit has landed.\n\
8. Ground any edit tool call in the current likely patch file snapshot.\n\
9. If you use `filesystem__write_file` for a code edit, omit `line_number` and provide the full updated file contents.\n",
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

fn collect_goal_literals(goal: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut current = String::new();
    let mut delimiter: Option<char> = None;

    for ch in goal.chars() {
        if let Some(active) = delimiter {
            if ch == active {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    literals.push(trimmed.to_string());
                }
                current.clear();
                delimiter = None;
            } else {
                current.push(ch);
            }
            continue;
        }

        if matches!(ch, '"' | '\'' | '`') {
            delimiter = Some(ch);
        }
    }

    literals
}

fn split_parent_playbook_context(goal: &str) -> (&str, Option<&str>) {
    if let Some((head, tail)) = goal.split_once("[PARENT PLAYBOOK CONTEXT]") {
        (head.trim(), Some(tail.trim()))
    } else {
        (goal.trim(), None)
    }
}

fn normalize_worker_context_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

fn extract_worker_context_field(text: &str, keys: &[&str]) -> Option<String> {
    let normalized_keys = keys
        .iter()
        .map(|key| normalize_worker_context_key(key))
        .collect::<Vec<_>>();
    for line in text.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches('-')
            .trim_start_matches('*')
            .trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        if normalized_keys
            .iter()
            .any(|candidate| *candidate == normalize_worker_context_key(key))
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn looks_like_command_literal(literal: &str) -> bool {
    let trimmed = literal.trim();
    if trimmed.is_empty() || !trimmed.contains(' ') {
        return false;
    }

    let first = trimmed
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-');
    matches!(
        first,
        "python"
            | "python3"
            | "pytest"
            | "cargo"
            | "npm"
            | "pnpm"
            | "yarn"
            | "node"
            | "uv"
            | "go"
            | "bash"
            | "sh"
            | "make"
            | "just"
    )
}

fn first_goal_command_literal(goal: &str) -> Option<String> {
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
        .filter(|value| looks_like_command_literal(value))
    {
        return Some(command);
    }

    collect_goal_literals(goal)
        .into_iter()
        .find(|literal| looks_like_command_literal(literal))
}

fn patch_build_verify_likely_files(assignment: &WorkerAssignment) -> Vec<String> {
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

fn patch_build_verify_primary_patch_file(
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

fn patch_build_verify_explicit_target_path(raw_tool_output: &str) -> Option<String> {
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

fn patch_build_verify_current_file_snapshot(
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

fn looks_like_test_path(path: &str) -> bool {
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

fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn latest_command_failure_summary(agent_state: &AgentState) -> Option<String> {
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

fn latest_goal_command(agent_state: &AgentState, command_literal: &str) -> Option<(i32, u32)> {
    let target = normalize_whitespace(command_literal);
    agent_state.command_history.iter().rev().find_map(|entry| {
        let observed = normalize_whitespace(&entry.command);
        (observed == target || observed.contains(&target))
            .then_some((entry.exit_code, entry.step_index))
    })
}

fn command_history_contains_goal_command(agent_state: &AgentState, command_literal: &str) -> bool {
    latest_goal_command(agent_state, command_literal).is_some()
}

fn parse_receipt_step(value: &str) -> Option<u32> {
    value
        .split(';')
        .find_map(|segment| segment.trim().strip_prefix("step="))
        .and_then(|step| step.parse::<u32>().ok())
}

fn latest_workspace_edit_step(agent_state: &AgentState) -> Option<u32> {
    match agent_state
        .tool_execution_log
        .get("receipt::workspace_edit_applied=true")
    {
        Some(ToolCallStatus::Executed(value)) => parse_receipt_step(value),
        _ => None,
    }
}

fn latest_workspace_edit_path(agent_state: &AgentState) -> Option<String> {
    match agent_state
        .tool_execution_log
        .get("receipt::workspace_edit_applied=true")
    {
        Some(ToolCallStatus::Executed(value)) => parse_receipt_path(value).map(str::to_string),
        _ => None,
    }
}

fn latest_workspace_read_step(agent_state: &AgentState, target_path: &str) -> Option<u32> {
    execution_receipt_value(&agent_state.tool_execution_log, "workspace_read_observed").and_then(
        |value| {
            (parse_receipt_path(value)? == target_path)
                .then(|| parse_receipt_step(value))
                .flatten()
        },
    )
}

fn parse_receipt_path<'a>(value: &'a str) -> Option<&'a str> {
    value
        .split(';')
        .find_map(|segment| segment.trim().strip_prefix("path="))
        .map(str::trim)
        .filter(|path| !path.is_empty())
}

fn latest_workspace_patch_miss_step(agent_state: &AgentState, target_path: &str) -> Option<u32> {
    execution_receipt_value(
        &agent_state.tool_execution_log,
        "workspace_patch_miss_observed",
    )
    .and_then(|value| {
        (parse_receipt_path(value)? == target_path)
            .then(|| parse_receipt_step(value))
            .flatten()
    })
}

fn patch_build_verify_refresh_read_ready(agent_state: &AgentState, target_path: &str) -> bool {
    let Some(patch_miss_step) = latest_workspace_patch_miss_step(agent_state, target_path) else {
        return false;
    };

    latest_workspace_read_step(agent_state, target_path)
        .map(|read_step| patch_miss_step > read_step)
        .unwrap_or(true)
}

fn raw_tool_output_requests_refresh_read(raw_tool_output: &str, target_path: &str) -> bool {
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
            || normalized.contains("filesystem__read_file")
            || normalized.contains("current file"))
}

fn goal_command_retry_ready_after_workspace_edit(
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

fn patch_build_verify_completion_ready(
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

fn synthesize_patch_build_verify_completion_result(
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

fn looks_like_planning_restatement(raw_tool_output: &str) -> bool {
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

fn extract_fenced_code_blocks(raw_tool_output: &str) -> Vec<String> {
    let normalized = raw_tool_output.replace("\r\n", "\n");
    let parts = normalized.split("```").collect::<Vec<_>>();
    let mut code_blocks = Vec::new();
    for index in (1..parts.len()).step_by(2) {
        let segment = parts[index].trim_start_matches('\n');
        if segment.trim().is_empty() {
            continue;
        }
        let mut lines = segment.lines();
        let first_line = lines.next().unwrap_or_default();
        let code = if looks_like_code_fence_language(first_line) {
            lines.collect::<Vec<_>>().join("\n")
        } else {
            segment.to_string()
        };
        let block = code.trim_matches('\n').to_string();
        if !block.trim().is_empty() {
            code_blocks.push(block);
        }
    }
    code_blocks
}

fn extract_fenced_python_function_blocks(raw_tool_output: &str) -> Vec<String> {
    extract_fenced_code_blocks(raw_tool_output)
        .into_iter()
        .filter_map(|block| {
            let normalized = normalize_code_block_content(&block);
            extract_primary_python_function_block(&normalized).or_else(|| {
                let first_line = normalized.lines().find(|line| !line.trim().is_empty())?;
                if matches_python_function_signature(first_line.trim_start()) {
                    Some(normalized)
                } else {
                    None
                }
            })
        })
        .collect()
}

fn split_inline_python_body(trailing: &str) -> Vec<String> {
    let mut remaining = trailing.trim();
    let mut lines = Vec::new();
    for quote in ["\"\"\"", "'''"] {
        if remaining.starts_with(quote) {
            if let Some(end_idx) = remaining[quote.len()..].find(quote) {
                let end = quote.len() + end_idx + quote.len();
                lines.push(remaining[..end].to_string());
                remaining = remaining[end..].trim();
            }
            break;
        }
    }
    if !remaining.is_empty() {
        lines.push(remaining.to_string());
    }
    lines
}

fn split_inline_python_signature_body(line: &str) -> Option<(String, Vec<String>)> {
    let trimmed = line.trim_start();
    if !matches_python_function_signature(trimmed) {
        return None;
    }

    let colon_idx = trimmed.rfind(':')?;
    let trailing = trimmed[colon_idx + 1..].trim();
    if trailing.is_empty() {
        return None;
    }

    Some((
        trimmed[..=colon_idx].trim_end().to_string(),
        split_inline_python_body(trailing),
    ))
}

fn expand_inline_python_function_block(block: &str) -> String {
    let normalized = normalize_code_block_content(block);
    let mut lines = normalized.lines();
    let Some(first_line) = lines.next() else {
        return normalized;
    };
    let Some((header, body_lines)) = split_inline_python_signature_body(first_line) else {
        return normalized;
    };

    let signature_indent = indentation_prefix(first_line);
    let body_indent = format!("{signature_indent}    ");
    let mut expanded = vec![format!("{signature_indent}{header}")];
    for body_line in body_lines {
        expanded.push(format!("{body_indent}{body_line}"));
    }
    expanded.extend(lines.map(str::to_string));
    expanded.join("\n")
}

fn extract_inline_python_function_blocks(
    current_block: &str,
    raw_tool_output: &str,
) -> Vec<String> {
    let Some(function_name) = python_function_name_from_block(current_block) else {
        return Vec::new();
    };

    let lines = raw_tool_output
        .replace("\r\n", "\n")
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();

    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            let signature_start = trimmed.find(&format!("{function_name}("))?;
            let candidate_suffix = trimmed[signature_start..].trim();
            if candidate_suffix.is_empty() {
                return None;
            }

            let mut candidate_lines = vec![if candidate_suffix.starts_with("def ")
                || candidate_suffix.starts_with("async def ")
            {
                candidate_suffix.to_string()
            } else {
                format!("def {candidate_suffix}")
            }];
            for following in lines.iter().skip(index + 1) {
                let trimmed_following = following.trim();
                if trimmed_following.is_empty()
                    || trimmed_following.starts_with("```")
                    || trimmed_following.starts_with("sys__")
                    || trimmed_following.starts_with("filesystem__")
                    || trimmed_following.starts_with("agent__")
                    || trimmed_following.starts_with('{')
                    || trimmed_following.starts_with('[')
                    || matches_python_function_signature(trimmed_following)
                {
                    break;
                }
                if !looks_like_inline_python_body_line(trimmed_following) {
                    break;
                }
                candidate_lines.push(trimmed_following.to_string());
            }

            let expanded = expand_inline_python_function_block(&candidate_lines.join("\n"));
            python_blocks_reference_same_function(current_block, &expanded).then_some(expanded)
        })
        .collect()
}

fn default_python_body_indent_base(lines: &[&str]) -> Option<usize> {
    lines
        .first()
        .map(|signature| leading_whitespace_count(signature).saturating_add(4))
}

fn looks_like_inline_python_body_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    trimmed.starts_with("return ")
        || trimmed.starts_with("if ")
        || trimmed.starts_with("elif ")
        || trimmed == "else:"
        || trimmed.starts_with("for ")
        || trimmed.starts_with("while ")
        || trimmed.starts_with("with ")
        || trimmed == "try:"
        || trimmed.starts_with("except ")
        || trimmed == "finally:"
        || trimmed.starts_with("raise ")
        || trimmed == "pass"
        || trimmed == "break"
        || trimmed == "continue"
        || trimmed.starts_with("assert ")
        || trimmed.starts_with("\"\"\"")
        || trimmed.starts_with("'''")
        || trimmed.ends_with(':')
        || (trimmed.contains('=') && !trimmed.contains('`'))
}

fn looks_like_code_fence_language(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 24
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+' | '#' | '.'))
}

fn normalize_code_block_content(block: &str) -> String {
    block.replace("\r\n", "\n").trim_matches('\n').to_string()
}

fn extract_primary_python_function_block(file_content: &str) -> Option<String> {
    let normalized = file_content.replace("\r\n", "\n");
    let lines = normalized.lines().collect::<Vec<_>>();
    let start = lines
        .iter()
        .position(|line| matches_python_function_signature(line.trim_start()))?;
    let base_indent = lines[start]
        .chars()
        .take_while(|ch| ch.is_whitespace())
        .count();
    let mut end = lines.len();
    for (offset, line) in lines.iter().enumerate().skip(start + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
        if indent <= base_indent && !line.trim_start().starts_with('@') {
            end = offset;
            break;
        }
    }
    let block = lines[start..end].join("\n");
    let normalized = normalize_code_block_content(&block);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn inline_python_block_repair_candidate(
    current_block: &str,
    raw_tool_output: &str,
) -> Option<String> {
    let normalized_block = normalize_code_block_content(current_block);
    let signature_line = normalized_block.lines().next()?.trim();
    if !matches_python_function_signature(signature_line) {
        return None;
    }
    let updated_return = extract_inline_python_return_line(raw_tool_output)?;
    inline_python_block_repair_candidate_from_line(current_block, &updated_return)
}

fn updated_python_block_candidate_from_raw_output(
    current_block: &str,
    raw_tool_output: &str,
) -> Option<String> {
    if let Some(block) = extract_fenced_python_function_blocks(raw_tool_output)
        .into_iter()
        .rev()
        .find_map(|block| {
            if !python_blocks_reference_same_function(current_block, &block) {
                return None;
            }
            align_python_block_to_reference(&block, current_block)
        })
    {
        return Some(block);
    }

    if let Some(block) = extract_inline_python_function_blocks(current_block, raw_tool_output)
        .into_iter()
        .rev()
        .find_map(|block| align_python_block_to_reference(&block, current_block))
    {
        return Some(block);
    }

    inline_python_block_repair_candidate(current_block, raw_tool_output)
}

fn inline_python_block_repair_candidate_from_line(
    current_block: &str,
    updated_return: &str,
) -> Option<String> {
    let normalized_block = normalize_code_block_content(current_block);
    let mut replaced = false;
    let updated_lines = normalized_block
        .lines()
        .map(|line| {
            if !replaced && line.trim_start().starts_with("return ") {
                replaced = true;
                format!("{}{}", indentation_prefix(line), updated_return.trim())
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>();
    if !replaced {
        return None;
    }

    Some(normalize_replacement_block(
        current_block,
        &updated_lines.join("\n"),
    ))
}

fn extract_inline_python_return_line(raw_tool_output: &str) -> Option<String> {
    raw_tool_output
        .replace("\r\n", "\n")
        .lines()
        .rev()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with("```")
                || trimmed.starts_with("sys__")
                || trimmed.starts_with('{')
                || trimmed.starts_with('[')
            {
                return None;
            }
            let start = trimmed.find("return ")?;
            let candidate = trimmed[start..].trim();
            if candidate.contains("filesystem__") || candidate.contains("agent__") {
                return None;
            }
            Some(candidate.to_string())
        })
}

fn python_blocks_reference_same_function(left: &str, right: &str) -> bool {
    python_function_name_from_block(left)
        .zip(python_function_name_from_block(right))
        .is_some_and(|(left, right)| left == right)
}

fn python_function_name_from_block(block: &str) -> Option<String> {
    block
        .lines()
        .find_map(|line| python_function_name_from_signature(line.trim_start()))
}

fn python_function_name_from_signature(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed
        .strip_prefix("def ")
        .or_else(|| trimmed.strip_prefix("async def "))?;
    let candidate = rest.split('(').next()?.trim();
    if candidate.is_empty()
        || !candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(candidate.to_string())
}

fn python_function_primary_parameter_name(signature_line: &str) -> Option<String> {
    let trimmed = signature_line.trim();
    let rest = trimmed
        .strip_prefix("def ")
        .or_else(|| trimmed.strip_prefix("async def "))?;
    let params = rest.split_once('(')?.1.split_once(')')?.0;
    let candidate = params.split(',').next()?.split(':').next()?.trim();
    if candidate.is_empty()
        || !candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(candidate.to_string())
}

fn is_single_line_python_docstring(line: &str) -> bool {
    let trimmed = line.trim();
    (trimmed.starts_with("\"\"\"") && trimmed.ends_with("\"\"\"") && trimmed.len() >= 6)
        || (trimmed.starts_with("'''") && trimmed.ends_with("'''") && trimmed.len() >= 6)
}

fn patch_build_verify_path_parity_reference_repair(reference_block: &str) -> Option<String> {
    let reference = expand_inline_python_function_block(reference_block);
    let reference_lines = reference.lines().collect::<Vec<_>>();
    let signature_line = reference_lines.first()?.trim_start();
    if !matches_python_function_signature(signature_line) {
        return None;
    }

    let path_var = python_function_primary_parameter_name(signature_line)?;
    let signature_prefix = indentation_prefix(reference_lines.first()?);
    let body_indent = python_body_indent_base(&reference_lines)
        .or_else(|| default_python_body_indent_base(&reference_lines))
        .unwrap_or(signature_prefix.len() + 4);
    let branch_indent = body_indent + 4;
    let indent = " ".repeat(body_indent);
    let nested_indent = " ".repeat(branch_indent);

    let mut repaired_lines = vec![format!("{signature_prefix}{signature_line}")];
    if let Some(docstring) = reference_lines
        .iter()
        .skip(1)
        .map(|line| line.trim())
        .find(|line| is_single_line_python_docstring(line))
    {
        repaired_lines.push(format!("{indent}{docstring}"));
    }
    repaired_lines.push(format!("{indent}prefix = \"\""));
    repaired_lines.push(format!(r#"{indent}if {path_var}.startswith("./"):"#));
    repaired_lines.push(format!(r#"{nested_indent}prefix = "./""#));
    repaired_lines.push(format!(r#"{nested_indent}{path_var} = {path_var}[2:]"#));
    repaired_lines.push(format!(r#"{indent}elif {path_var}.startswith("/"):"#));
    repaired_lines.push(format!(r#"{nested_indent}prefix = "/""#));
    repaired_lines.push(format!(r#"{nested_indent}{path_var} = {path_var}[1:]"#));
    repaired_lines.push(format!(
        r#"{indent}normalized = {path_var}.replace("\\", "/")"#
    ));
    repaired_lines.push(format!(r#"{indent}while "//" in normalized:"#));
    repaired_lines.push(format!(
        r#"{nested_indent}normalized = normalized.replace("//", "/")"#
    ));
    repaired_lines.push(format!(r#"{indent}return prefix + normalized"#));

    Some(normalize_replacement_block(
        reference_block,
        &repaired_lines.join("\n"),
    ))
}

fn align_python_block_to_reference(candidate_block: &str, reference_block: &str) -> Option<String> {
    let candidate = expand_inline_python_function_block(candidate_block);
    let reference = expand_inline_python_function_block(reference_block);
    let candidate_lines = candidate.lines().collect::<Vec<_>>();
    let reference_lines = reference.lines().collect::<Vec<_>>();
    let candidate_signature = candidate_lines.first()?.trim_start();
    let reference_signature = reference_lines.first()?.trim_start();
    if !matches_python_function_signature(candidate_signature)
        || !matches_python_function_signature(reference_signature)
        || !python_blocks_reference_same_function(&candidate, &reference)
    {
        return None;
    }

    let signature_prefix = indentation_prefix(reference_lines.first()?);
    let reference_body_base = python_body_indent_base(&reference_lines)
        .or_else(|| default_python_body_indent_base(&reference_lines))?;
    let candidate_body_base = python_body_indent_base(&candidate_lines)
        .or_else(|| default_python_body_indent_base(&candidate_lines))
        .unwrap_or(reference_body_base);
    let mut aligned_lines = Vec::with_capacity(candidate_lines.len());
    aligned_lines.push(format!("{signature_prefix}{candidate_signature}"));

    for line in candidate_lines.iter().skip(1) {
        if line.trim().is_empty() {
            aligned_lines.push(String::new());
            continue;
        }
        let relative_indent = leading_whitespace_count(line).saturating_sub(candidate_body_base);
        let aligned_indent = format!(
            "{}{}",
            " ".repeat(reference_body_base),
            " ".repeat(relative_indent)
        );
        aligned_lines.push(format!("{}{}", aligned_indent, line.trim_start()));
    }

    Some(normalize_replacement_block(
        reference_block,
        &aligned_lines.join("\n"),
    ))
}

fn matches_python_function_signature(line: &str) -> bool {
    line.starts_with("def ") || line.starts_with("async def ")
}

fn indentation_prefix(line: &str) -> &str {
    let count = line.chars().take_while(|ch| ch.is_whitespace()).count();
    &line[..count]
}

fn leading_whitespace_count(line: &str) -> usize {
    line.chars().take_while(|ch| ch.is_whitespace()).count()
}

fn python_body_indent_base(lines: &[&str]) -> Option<usize> {
    lines
        .iter()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| leading_whitespace_count(line))
        .min()
}

fn patch_search_block(file_content: &str, current_block: &str) -> Option<String> {
    if current_block.is_empty() {
        return None;
    }
    if file_content.matches(current_block).count() == 1 {
        return Some(current_block.to_string());
    }

    let trimmed_block = current_block.trim();
    if trimmed_block.is_empty() {
        return None;
    }
    if file_content.trim() == trimmed_block {
        return Some(file_content.to_string());
    }
    if file_content.matches(trimmed_block).count() == 1 {
        return Some(trimmed_block.to_string());
    }

    None
}

fn normalize_block_for_match(block: &str) -> String {
    block
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

fn normalize_replacement_block(search: &str, replace: &str) -> String {
    let mut normalized = replace.replace("\r\n", "\n").trim_matches('\n').to_string();
    if search.ends_with('\n') && !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

fn truncate_for_prompt(value: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    let mut truncated = trimmed.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn sanitize_check_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_whitespace() { '_' } else { ch })
        .take(96)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        attempt_invalid_tool_call_repair, attempt_patch_build_verify_runtime_patch_miss_repair,
        attempt_refusal_repair, invalid_tool_repair_supported,
        maybe_rewrite_patch_build_verify_post_success_completion,
        maybe_rewrite_patch_build_verify_redundant_refresh_read,
        upconvert_patch_build_verify_runtime_line_edit_repair,
        updated_python_block_candidate_from_raw_output,
    };
    use crate::agentic::desktop::keys::get_state_key;
    use crate::agentic::desktop::service::lifecycle::persist_worker_assignment;
    use crate::agentic::desktop::service::step::action::mark_execution_receipt_with_value;
    use crate::agentic::desktop::service::DesktopAgentService;
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier, ToolCallStatus,
        WorkerAssignment, WorkerCompletionContract, WorkerMergeMode,
    };
    use async_trait::async_trait;
    use image::{ImageBuffer, ImageFormat, Rgba};
    use ioi_api::state::StateAccess;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::{
        EmbeddingResult, ImageEditRequest, ImageEmbeddingRequest, ImageGenerationRequest,
        ImageGenerationResult, InferenceRuntime, ModelLifecycleResult, ModelLoadRequest,
        ModelUnloadRequest, RerankRequest, RerankResult, SpeechSynthesisRequest,
        SpeechSynthesisResult, TextGenerationRequest, TextGenerationResult, TranscriptionRequest,
        TranscriptionResult, VideoGenerationRequest, VideoGenerationResult, VisionReadRequest,
        VisionReadResult,
    };
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::agentic::{
        AgentTool, InferenceOptions, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };
    use ioi_types::app::ContextSlice;
    use ioi_types::codec;
    use ioi_types::error::VmError;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io::Cursor;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[derive(Clone)]
    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
            img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
            let mut bytes = Vec::new();
            img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
                .map_err(|error| {
                    VmError::HostError(format!("mock PNG encode failed: {}", error))
                })?;
            Ok(bytes)
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            self.capture_screen(None).await
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Ok("<root/>".to_string())
        }

        async fn capture_context(
            &self,
            _intent: &ioi_types::app::ActionRequest,
        ) -> Result<ContextSlice, VmError> {
            Ok(ContextSlice {
                slice_id: [0u8; 32],
                frame_id: 0,
                chunks: vec![b"<root/>".to_vec()],
                mhnsw_root: [0u8; 32],
                traversal_proof: None,
                intent_id: [0u8; 32],
            })
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Ok(())
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RepairRecordingRuntime {
        outputs: Mutex<Vec<Result<Vec<u8>, VmError>>>,
        seen_tools: Mutex<Vec<Vec<String>>>,
        seen_inputs: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait]
    impl InferenceRuntime for RepairRecordingRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            self.seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .push(input_context.to_vec());
            self.seen_tools
                .lock()
                .expect("seen_tools mutex poisoned")
                .push(options.tools.iter().map(|tool| tool.name.clone()).collect());
            let mut outputs = self.outputs.lock().expect("outputs mutex poisoned");
            if outputs.is_empty() {
                return Err(VmError::HostError("no repair output queued".to_string()));
            }
            outputs.remove(0)
        }

        async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
            Ok(vec![text.len() as f32, 1.0])
        }

        async fn embed_image(&self, _image_bytes: &[u8]) -> Result<Vec<f32>, VmError> {
            Ok(vec![1.0])
        }

        async fn generate_text(
            &self,
            request: TextGenerationRequest,
        ) -> Result<TextGenerationResult, VmError> {
            Ok(TextGenerationResult {
                output: request.input_context,
                model_id: request.model_id,
                streamed: request.stream,
            })
        }

        async fn rerank(&self, _request: RerankRequest) -> Result<RerankResult, VmError> {
            Err(VmError::HostError("rerank not supported".to_string()))
        }

        async fn transcribe_audio(
            &self,
            _request: TranscriptionRequest,
        ) -> Result<TranscriptionResult, VmError> {
            Err(VmError::HostError("transcribe not supported".to_string()))
        }

        async fn synthesize_speech(
            &self,
            _request: SpeechSynthesisRequest,
        ) -> Result<SpeechSynthesisResult, VmError> {
            Err(VmError::HostError("speech not supported".to_string()))
        }

        async fn vision_read(
            &self,
            _request: VisionReadRequest,
        ) -> Result<VisionReadResult, VmError> {
            Err(VmError::HostError("vision not supported".to_string()))
        }

        async fn generate_image(
            &self,
            _request: ImageGenerationRequest,
        ) -> Result<ImageGenerationResult, VmError> {
            Err(VmError::HostError(
                "image generation not supported".to_string(),
            ))
        }

        async fn edit_image(
            &self,
            _request: ImageEditRequest,
        ) -> Result<ImageGenerationResult, VmError> {
            Err(VmError::HostError("image edit not supported".to_string()))
        }

        async fn generate_video(
            &self,
            _request: VideoGenerationRequest,
        ) -> Result<VideoGenerationResult, VmError> {
            Err(VmError::HostError(
                "video generation not supported".to_string(),
            ))
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn build_worker_state(session_id: [u8; 32]) -> AgentState {
        AgentState {
            session_id,
            goal: "Implement the parity fix.".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 4,
            last_action_type: None,
            parent_session_id: Some([9u8; 32]),
            child_session_ids: Vec::new(),
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 1,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![
                "attempt::NoEffectAfterAction::first".to_string(),
                "attempt::UnexpectedState::second".to_string(),
            ],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: Vec::new(),
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
            pending_search_completion: None,
            planner_state: None,
        }
    }

    fn patch_assignment() -> WorkerAssignment {
        WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 24,
            goal: "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string(),
            success_criteria: "Patch the bug and verify it.".to_string(),
            max_retries: 0,
            retries_used: 0,
            assigned_session_id: Some([0x77; 32]),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "filesystem__read_file".to_string(),
                "filesystem__write_file".to_string(),
                "filesystem__edit_line".to_string(),
                "filesystem__search".to_string(),
                "filesystem__list_directory".to_string(),
                "filesystem__stat".to_string(),
                "filesystem__patch".to_string(),
                "sys__exec_session".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Patch the bug and verify it.".to_string(),
                expected_output: "Patched and verified.".to_string(),
                merge_mode: WorkerMergeMode::AppendAsEvidence,
                verification_hint: None,
            },
        }
    }

    fn patch_assignment_with_allowed_tools(allowed_tools: Vec<&str>) -> WorkerAssignment {
        let mut assignment = patch_assignment();
        assignment.allowed_tools = allowed_tools.into_iter().map(str::to_string).collect();
        assignment
    }

    fn patch_assignment_with_path_parity_goal() -> WorkerAssignment {
        let mut assignment = patch_assignment();
        assignment.goal = concat!(
            "Port the path-normalization parity fix into the repo root. Patch only `path_utils.py`, ",
            "keep `tests/test_path_utils.py` unchanged, update `normalize_fixture_path` so it ",
            "converts backslashes to forward slashes, collapses duplicate separators, and preserves ",
            "a leading `./` or `/`, then rerun `python3 -m unittest tests.test_path_utils -v` after the edit.\n\n",
            "[PARENT PLAYBOOK CONTEXT]\n",
            "- likely_files: path_utils.py; tests/test_path_utils.py\n",
            "- targeted_checks: python3 -m unittest tests.test_path_utils -v"
        )
        .to_string();
        assignment
    }

    fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "test".to_string(),
            scope,
            band: IntentConfidenceBand::High,
            score: 0.92,
            top_k: vec![],
            required_capabilities: vec![],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: None,
            constrained: false,
        }
    }

    fn record_targeted_check_failure(worker_state: &mut AgentState) {
        worker_state
            .command_history
            .push_back(crate::agentic::desktop::types::CommandExecution {
                command: "python3 -m unittest tests.test_path_utils -v".to_string(),
                exit_code: 1,
                stdout: String::new(),
                stderr: String::new(),
                timestamp_ms: 1,
                step_index: 0,
            });
    }

    #[test]
    fn invalid_tool_repair_support_stays_on_coding_scopes() {
        let mut agent_state = build_worker_state([0x11; 32]);
        assert!(invalid_tool_repair_supported(
            &agent_state,
            Some(&patch_assignment())
        ));

        agent_state.resolved_intent = Some(resolved(IntentScopeProfile::CommandExecution));
        assert!(invalid_tool_repair_supported(&agent_state, None));

        agent_state.resolved_intent = Some(resolved(IntentScopeProfile::WebResearch));
        assert!(!invalid_tool_repair_supported(&agent_state, None));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_uses_recovery_filtered_tools() {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","search":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path","replace":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path.strip().replace(\"\\\\\", \"/\")"}}"#
                    .to_vec(),
            ));
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x22; 32];
        let key = get_state_key(&session_id);
        let worker_state = build_worker_state(session_id);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        let mut assignment = patch_assignment();
        assignment.goal = concat!(
            "Port the path-normalization parity fix into the repo root. Patch only `path_utils.py`, ",
            "keep `tests/test_path_utils.py` unchanged, update `normalize_fixture_path` so it ",
            "converts backslashes to forward slashes, collapses duplicate separators, and preserves ",
            "a leading `./` or `/`, then rerun `python3 -m unittest tests.test_path_utils -v` after the edit.\n\n",
            "[PARENT PLAYBOOK CONTEXT]\n",
            "- likely_files: path_utils.py; tests/test_path_utils.py\n",
            "- targeted_checks: python3 -m unittest tests.test_path_utils -v"
        )
        .to_string();
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "portun normalize_fixture_path(raw_path: str) -> str: return raw_path.strip().replace(\"\\\\\", \"/\")",
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        assert_eq!(
            repair
                .repaired_tool
                .expect("expected repaired tool")
                .name_string(),
            "filesystem__patch"
        );
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "invalid_tool_call_repair_attempted=true"));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "invalid_tool_call_repair_runtime=fast"));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "invalid_tool_call_repair_succeeded=true"));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "invalid_tool_call_repair_tool=filesystem__patch"));

        let seen_tools = runtime
            .seen_tools
            .lock()
            .expect("seen_tools mutex poisoned")
            .clone();
        let repair_tools = seen_tools
            .iter()
            .find(|tool_names: &&Vec<String>| {
                tool_names
                    .iter()
                    .any(|name| name == "filesystem__write_file")
            })
            .expect("repair inference should record a tool set");
        assert!(repair_tools
            .iter()
            .any(|name| name == "filesystem__write_file"));
        assert!(repair_tools
            .iter()
            .any(|name| name == "filesystem__edit_line"));
        assert!(repair_tools.iter().any(|name| name == "filesystem__patch"));
        assert!(repair_tools.iter().any(|name| name == "sys__exec_session"));
        assert!(repair_tools.iter().any(|name| name == "agent__complete"));
        assert!(repair_tools.iter().any(|name| name == "system__fail"));
        assert!(!repair_tools
            .iter()
            .any(|name| name == "filesystem__read_file"));
        assert!(!repair_tools.iter().any(|name| name == "filesystem__search"));
        assert!(!repair_tools
            .iter()
            .any(|name| name == "filesystem__list_directory"));
        assert!(!repair_tools.iter().any(|name| name == "filesystem__stat"));

        let seen_inputs = runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .clone();
        let prompt = seen_inputs
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
            .find(|input: &String| input.contains("Malformed response to repair"))
            .expect("repair prompt should be recorded");
        assert!(prompt.contains("path_utils.py"));
        assert!(prompt.contains("filesystem__patch"));
        assert!(prompt.contains("JSON Syntax Error"));
    }

    #[test]
    fn patch_build_verify_deterministic_allowed_tool_names_rehydrates_edit_tools_from_assignment() {
        let mut worker_state = build_worker_state([0x23; 32]);
        record_targeted_check_failure(&mut worker_state);
        let assignment = patch_assignment_with_path_parity_goal();
        let allowed_tool_names = [
            "filesystem__read_file".to_string(),
            "sys__exec_session".to_string(),
            "agent__complete".to_string(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let mut verification_checks = Vec::new();

        let hydrated = super::patch_build_verify_deterministic_allowed_tool_names(
            &worker_state,
            Some(&assignment),
            &allowed_tool_names,
            &mut verification_checks,
            "invalid_tool_call_repair",
        );

        assert!(hydrated.contains("filesystem__write_file"));
        assert!(hydrated.contains("filesystem__edit_line"));
        assert!(hydrated.contains("filesystem__read_file"));
        assert!(verification_checks.iter().any(|check| {
            check
                == "invalid_tool_call_repair_deterministic_assignment_tool_hints=filesystem__write_file|filesystem__edit_line"
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_synthesizes_targeted_exec_before_runtime() {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x55; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "portun normalize_fixture_path(raw_path: str) -> str: ",
                "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
                "return raw_path.strip().replace(\"\\\\\", \"/\")\n\n",
                "Given that the function already replaces backslashes with forward slashes, ",
                "we need to ensure it also collapses duplicate separators and preserves a leading `./` or `/`.\n\n",
                "First, I will read the `path_utils.py` file to inspect its current state.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::SysExecSession {
                command,
                args,
                stdin,
            } => {
                assert_eq!(command, "bash");
                assert_eq!(
                    args,
                    vec![
                        "-lc".to_string(),
                        "python3 -m unittest tests.test_path_utils -v".to_string()
                    ]
                );
                assert_eq!(stdin, None);
            }
            other => panic!("expected sys__exec_session, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec"
        }));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| { check == "invalid_tool_call_repair_runtime=deterministic" }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_synthesizes_targeted_exec_after_initial_duplicate_read_guidance(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x54; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = ".".to_string();
        worker_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            r#"{"arguments":{"content":"tool: def normalize_fixture_path(raw_path: str) -> str:\n return raw_path.strip().replace(\"\\\\\", \"/\")","line_number":"0","path":"path_utils.py"},"name":"filesystem__edit_line"}"#,
            "Failed to parse tool call: filesystem__edit_line requires integer 'line_number' (or alias 'line')",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::SysExecSession {
                command,
                args,
                stdin,
            } => {
                assert_eq!(command, "bash");
                assert_eq!(
                    args,
                    vec![
                        "-lc".to_string(),
                        "python3 -m unittest tests.test_path_utils -v".to_string()
                    ]
                );
                assert_eq!(stdin, None);
            }
            other => panic!("expected sys__exec_session, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec"
        }));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "invalid_tool_call_repair_runtime=deterministic"));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_does_not_replay_targeted_exec_after_command_failure(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","search":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    return raw_path.strip().replace(\"\\\\\", \"/\")","replace":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    return raw_path.replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"}}"#
                    .to_vec(),
            ));
        runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
                    .to_vec(),
            ));
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x56; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "normalize_fixture_path currently replaces backslashes with forward slashes, ",
                "but does not collapse duplicate separators.\n\n",
                "Let's first read `path_utils.py` and update the function.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        assert_eq!(
            repair
                .repaired_tool
                .expect("expected repaired tool")
                .name_string(),
            "filesystem__write_file"
        );
        assert!(!repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_patch_tool_suppressed_after_command_failure=true"
        }));
        assert!(runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_replays_targeted_exec_after_workspace_edit_receipt(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x5f; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = ".".to_string();
        worker_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
        record_targeted_check_failure(&mut worker_state);
        worker_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            ToolCallStatus::Executed(
                "step=2;tool=filesystem__write_file;path=path_utils.py".to_string(),
            ),
        );
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "We already landed the path normalization edit. ",
                "Next I should rerun the focused verification command.\n",
                "1. Re-run the targeted tests.\n",
                "2. Confirm they pass.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::SysExecSession {
                command,
                args,
                stdin,
            } => {
                assert_eq!(command, "bash");
                assert_eq!(
                    args,
                    vec![
                        "-lc".to_string(),
                        "python3 -m unittest tests.test_path_utils -v".to_string()
                    ]
                );
                assert_eq!(stdin, None);
            }
            other => panic!("expected sys__exec_session, got {:?}", other),
        }
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| { check == "invalid_tool_call_repair_targeted_command_rerun=post_edit" }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_replays_targeted_exec_after_post_edit_unexpected_state(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x73; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = ".".to_string();
        worker_state.recent_actions = vec![
            "attempt::NoEffectAfterAction::first".to_string(),
            "attempt::UnexpectedState::second".to_string(),
        ];
        record_targeted_check_failure(&mut worker_state);
        worker_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            ToolCallStatus::Executed(
                "step=4;tool=filesystem__write_file;path=path_utils.py".to_string(),
            ),
        );
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "The edit is already in place.\n",
                "Now rerun the focused verifier and then finish with a bounded handoff.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::SysExecSession {
                command,
                args,
                stdin,
            } => {
                assert_eq!(command, "bash");
                assert_eq!(
                    args,
                    vec![
                        "-lc".to_string(),
                        "python3 -m unittest tests.test_path_utils -v".to_string()
                    ]
                );
                assert_eq!(stdin, None);
            }
            other => panic!("expected sys__exec_session, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_targeted_command_boundary=post_edit_unexpected_state"
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_prioritizes_targeted_exec_for_post_edit_code_blob(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x8a; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = ".".to_string();
        worker_state.recent_actions = vec![
            "attempt::NoEffectAfterAction::first".to_string(),
            "attempt::UnexpectedState::second".to_string(),
        ];
        record_targeted_check_failure(&mut worker_state);
        worker_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            ToolCallStatus::Executed(
                "step=5;tool=filesystem__write_file;path=path_utils.py".to_string(),
            ),
        );
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "portun normalize_fixture_path(raw_path: str) -> str: ",
                "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
                "prefix = \"\" if raw_path.startswith(\"./\"): prefix = \"./\" ",
                "raw_path = raw_path[2:] elif raw_path.startswith(\"/\"): prefix = \"/\" ",
                "raw_path = raw_path[1:] normalized = raw_path.replace(\"\\\\\", \"/\") ",
                "while \"//\" in normalized: normalized = normalized.replace(\"//\", \"/\") ",
                "return prefix + normalized\n\n",
                "The edit is already in place. First, I will read the file to ensure we have the correct context.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::SysExecSession {
                command,
                args,
                stdin,
            } => {
                assert_eq!(command, "bash");
                assert_eq!(
                    args,
                    vec![
                        "-lc".to_string(),
                        "python3 -m unittest tests.test_path_utils -v".to_string()
                    ]
                );
                assert_eq!(stdin, None);
            }
            other => panic!("expected sys__exec_session, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec"
        }));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| { check == "invalid_tool_call_repair_targeted_command_rerun=post_edit" }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[test]
    fn patch_build_verify_post_success_completion_rewrites_followup_patch_attempt() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x91; 32];
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = ".".to_string();
        worker_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 0,
            stdout: "OK".to_string(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 6,
        });
        worker_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            ToolCallStatus::Executed(
                "step=4;tool=filesystem__write_file;path=path_utils.py".to_string(),
            ),
        );

        let mut verification_checks = Vec::new();
        let rewritten = maybe_rewrite_patch_build_verify_post_success_completion(
            &state,
            &worker_state,
            session_id,
            &AgentTool::FsPatch {
                path: "path_utils.py".to_string(),
                search: "before".to_string(),
                replace: "after".to_string(),
            },
            &mut verification_checks,
        )
        .expect("expected completion rewrite");

        match rewritten {
            AgentTool::AgentComplete { result } => {
                assert!(result.contains("Touched files: path_utils.py"));
                assert!(result.contains(
                    "Verification: python3 -m unittest tests.test_path_utils -v (passed)"
                ));
                assert!(result.contains("broader checks were not rerun"));
            }
            other => panic!("expected agent__complete, got {:?}", other),
        }
        assert!(verification_checks
            .iter()
            .any(|check| { check == "patch_build_verify_post_success_completion_rewritten=true" }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_completes_after_successful_targeted_command() {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x92; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = ".".to_string();
        worker_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 0,
            stdout: "OK".to_string(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 8,
        });
        worker_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            ToolCallStatus::Executed(
                "step=4;tool=filesystem__write_file;path=path_utils.py".to_string(),
            ),
        );
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "I will patch path_utils.py again to be safe before wrapping up.",
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::AgentComplete { result } => {
                assert!(result.contains("Touched files: path_utils.py"));
                assert!(result.contains(
                    "Verification: python3 -m unittest tests.test_path_utils -v (passed)"
                ));
            }
            other => panic!("expected agent__complete, got {:?}", other),
        }
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| { check == "patch_build_verify_post_success_completion_rewritten=true" }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_synthesizes_code_block_write_before_runtime() {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x66; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "Based on the previous steps, we need to update the `normalize_fixture_path` ",
                "function in `path_utils.py`.\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.strip().replace(\"\\\\\", \"/\")\n",
                "```\n\n",
                "Here is the updated function:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"/\").lstrip(\"./\")\n",
                "```\n\n",
                "Now, let's apply this change using `filesystem__patch`.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        let repaired_tool = repair.repaired_tool.clone().unwrap_or_else(|| {
            panic!(
                "expected repaired tool; checks={:?}",
                repair.verification_checks
            )
        });

        match repaired_tool {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("prefix = \"./\""),
                    "content was: {content}"
                );
                assert!(
                    !content.contains("lstrip(\"./\")"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=code_block_write"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=fenced_code_blocks"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_aligns_code_block_indentation_before_runtime() {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x69; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "Based on the previous output, the current implementation is:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " return raw_path.strip().replace(\"\\\\\", \"/\")\n",
                "```\n\n",
                "The updated function should look like this:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " return raw_path.replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"/\").lstrip(\"./\")\n",
                "```\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        let repaired_tool = repair.repaired_tool.clone().unwrap_or_else(|| {
            panic!(
                "expected repaired tool; checks={:?}",
                repair.verification_checks
            )
        });

        match repaired_tool {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("\n    \"\"\"Normalize a repo-relative path"));
                assert!(content.contains("replace(\"//\", \"/\")"));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_alignment=python_function_indent"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_synthesizes_retained_multiblock_write_before_runtime(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x6b; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "portun normalize_fixture_path to convert backslashes to forward slashes, collapse duplicate separators, and preserve a leading ./ or /. The current implementation is:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " return raw_path.strip().replace(\"\\\\\", \"/\")\n",
                "```\n\n",
                "To achieve the goal, we need to update this function. Let's modify it to handle backslashes and duplicate separators correctly.\n\n",
                "First, let's edit line 8 of `path_utils.py`:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n",
                "```\n\n",
                "Now, let's use the `filesystem__edit_line` tool to make this change.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        let repaired_tool = repair.repaired_tool.clone().unwrap_or_else(|| {
            panic!(
                "expected repaired tool; checks={:?}",
                repair.verification_checks
            )
        });

        match repaired_tool {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("prefix = \"./\""),
                    "content was: {content}"
                );
                assert!(
                    !content.contains("lstrip(\"./\")"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=code_block_write"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_ignores_trailing_example_lines_in_fenced_block_before_runtime(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x6c; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "portun normalize_fixture_path to convert backslashes to forward slashes, collapse duplicate separators, and preserve a leading ./ or /. The current implementation is:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " return raw_path.strip().replace(\"\\\\\", \"/\")\n",
                "```\n\n",
                "The updated function should look like this:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " raw_path = raw_path.strip().replace(\"\\\\\", \"/\")\n",
                " while \"//\" in raw_path:\n",
                "  raw_path = raw_path.replace(\"//\", \"/\")\n",
                " return raw_path\n",
                "\n",
                "# Example usage and verification\n",
                "print(normalize_fixture_path(\"./foo//bar\"))\n",
                "```\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("while \"//\" in raw_path:"));
                assert!(content.contains("return raw_path"));
                assert!(!content.contains("print(normalize_fixture_path"));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_synthesizes_goal_constrained_snapshot_write_before_runtime(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        fs::write(
            &path_utils,
            concat!(
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\").lstrip(\"/\")\n"
            ),
        )
        .expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x7d; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "The focused verification command still shows one failing path-normalization case. ",
                "I will update `path_utils.py` to fully preserve the leading prefix while collapsing duplicate separators before rerunning tests."
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        let repaired_tool = repair.repaired_tool.clone().unwrap_or_else(|| {
            panic!(
                "expected repaired tool; checks={:?}",
                repair.verification_checks
            )
        });

        match repaired_tool {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("prefix = \"\""), "content was: {content}");
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("return prefix + normalized"),
                    "content was: {content}"
                );
                assert!(
                    !content.contains(".lstrip(\"./\")"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check
                == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_prefers_goal_snapshot_over_inline_code_segments_for_path_parity(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        fs::write(
            &path_utils,
            concat!(
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
            ),
        )
        .expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x7e; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "Given that the initial verification command failed, we need to update the ",
                "`normalize_fixture_path` function in `path_utils.py` to ensure it correctly ",
                "handles backslashes and collapses duplicate separators.\n\n",
                "Let's modify the function as follows:\n",
                "1. Replace all backslashes with forward slashes.\n",
                "2. Collapse any consecutive separators.\n",
                "3. Ensure a leading `./` or `/` is preserved.\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    normalized = raw_path.replace(\"\\\\\", \"/\")\n",
                "    import re\n",
                "    normalized = re.sub(r'/+', '/', normalized)\n",
                "    if not (normalized.startswith('./') or normalized.startswith('/')):\n",
                "        normalized = './' + normalized\n",
                "    return normalized\n",
                "```\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("prefix = \"\""), "content was: {content}");
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("return prefix + normalized"),
                    "content was: {content}"
                );
                assert!(
                    !content.contains("normalized = './' + normalized"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check
                == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
        }));
        assert!(!repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=inline_code_segments"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_deterministic_code_block_repair_rejects_goal_violating_candidate() {
        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut worker_state = build_worker_state([0x7c; 32]);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        let assignment = patch_assignment_with_path_parity_goal();
        let allowed_tool_names = assignment
            .allowed_tools
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let raw_tool_output = concat!(
            "Current implementation:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n",
            "```\n\n",
            "Updated implementation:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n",
            "```\n"
        );
        let mut verification_checks = Vec::new();
        let repaired_tool = super::synthesize_patch_build_verify_code_block_edit_repair(
            &worker_state,
            Some(&assignment),
            &allowed_tool_names,
            raw_tool_output,
            &mut verification_checks,
        )
        .expect("deterministic repair should be synthesized");

        let validated = super::validate_patch_build_verify_deterministic_edit_repair(
            &worker_state,
            Some(&assignment),
            raw_tool_output,
            repaired_tool,
            &mut verification_checks,
            "code_block",
        )
        .await
        .expect("validation should succeed");

        assert!(matches!(
            validated,
            super::DeterministicEditRepairValidation::Rejected(_)
        ));
        assert!(verification_checks.iter().any(|check| {
            check
                == "invalid_tool_call_repair_runtime_deterministic_code_block_goal_path_prefix_violation=true"
        }));
        assert!(verification_checks.iter().any(|check| {
            check
                == "invalid_tool_call_repair_deterministic_code_block_rejected=deterministic_code_block:goal_path_prefix_violation"
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_synthesizes_inline_code_write_before_runtime() {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x68; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "normalize_fixture_path(raw_path: str) -> str:\n",
                "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "normalized = raw_path.replace(\"\\\\\", \"/\").strip()\n",
                "return normalized\n\n",
                "# Verify the change\n",
                "sys__exec_session({\"command\": \"python3 -m unittest tests.test_path_utils -v\"})\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("normalized = raw_path.replace(\"\\\\\", \"/\").strip()"));
                assert!(content.contains("return normalized"));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=inline_code_write"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=inline_code_segments"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_recovers_exact_single_line_inline_edit_from_retained_trace(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x72; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "portun normalize_fixture_path(raw_path: str) -> str: ",
                "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
                "return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").strip(\"/\")\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("replace(\"//\", \"/\")"));
                assert!(content.contains("strip(\"/\")"));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=inline_code_write"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_synthesizes_refresh_read_after_patch_miss_prose(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x73; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        mark_execution_receipt_with_value(
            &mut worker_state.tool_execution_log,
            "workspace_patch_miss_observed",
            "step=7;tool=filesystem__patch;path=path_utils.py;reason=search_block_not_found"
                .to_string(),
        );
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "Fortunately, I will proceed by reading the `path_utils.py` file to identify the correct block of code to patch.\n\n",
                "First, let's read the content of `path_utils.py`.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsRead { path } => assert_eq!(path, "path_utils.py"),
            other => panic!("expected filesystem__read_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=refresh_read"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_upconverts_runtime_line_edit_to_full_write() {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                r#"{"name":"filesystem__edit_line","arguments":{"path":"/tmp/wrong/path_utils.py","line_number":6,"content":"return raw_path.replace(\"\\\\\", \"/\").strip()","text":"return raw_path.replace(\"\\\\\", \"/\").strip()"}} "#
                    .trim()
                    .as_bytes()
                    .to_vec(),
            ));
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x6a; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_allowed_tools(vec![
                "filesystem__write_file",
                "filesystem__edit_line",
                "sys__exec_session",
                "agent__complete",
            ]),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "I will update the function using filesystem__edit_line after the failing test.",
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("return raw_path.replace(\"\\\\\", \"/\").strip()"));
                assert!(!content.contains("return raw_path.strip().replace(\"\\\\\", \"/\")"));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_runtime_line_edit_upconverted=true"
        }));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "invalid_tool_call_repair_runtime=fast"));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            1
        );
    }

    #[test]
    fn patch_build_verify_runtime_line_edit_upconvert_prefers_retained_raw_output() {
        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let session_id = [0x6d; 32];
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();

        let repaired_tool = upconvert_patch_build_verify_runtime_line_edit_repair(
            &worker_state,
            Some(&patch_assignment_with_allowed_tools(vec![
                "filesystem__write_file",
                "filesystem__edit_line",
                "sys__exec_session",
                "agent__complete",
            ])),
            concat!(
                "portun normalize_fixture_path to convert backslashes to forward slashes, collapse duplicate separators, and preserve a leading ./ or /. The current implementation is:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " return raw_path.strip().replace(\"\\\\\", \"/\")\n",
                "```\n\n",
                "To achieve the goal, we need to update this function. Let's modify it to handle backslashes and duplicate separators correctly.\n\n",
                "First, let's edit line 8 of `path_utils.py`:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n",
                "```\n\n",
                "Now, let's use the `filesystem__edit_line` tool to make this change.\n"
            ),
            AgentTool::FsWrite {
                path: "/tmp/wrong/path_utils.py".to_string(),
                content: "First, let's edit line 8 of path_utils.py".to_string(),
                line_number: Some(8),
            },
            &mut Vec::new(),
        );

        match repaired_tool {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("replace(\"//\", \"/\")"));
                assert!(content.contains("lstrip(\"./\")"));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }

        let mut verification_checks = Vec::new();
        let _ = upconvert_patch_build_verify_runtime_line_edit_repair(
            &worker_state,
            Some(&patch_assignment_with_allowed_tools(vec![
                "filesystem__write_file",
                "filesystem__edit_line",
                "sys__exec_session",
                "agent__complete",
            ])),
            concat!(
                "portun normalize_fixture_path to convert backslashes to forward slashes, collapse duplicate separators, and preserve a leading ./ or /. The current implementation is:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " return raw_path.strip().replace(\"\\\\\", \"/\")\n",
                "```\n\n",
                "To achieve the goal, we need to update this function. Let's modify it to handle backslashes and duplicate separators correctly.\n\n",
                "First, let's edit line 8 of `path_utils.py`:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                " return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n",
                "```\n\n",
                "Now, let's use the `filesystem__edit_line` tool to make this change.\n"
            ),
            AgentTool::FsWrite {
                path: "/tmp/wrong/path_utils.py".to_string(),
                content: "First, let's edit line 8 of path_utils.py".to_string(),
                line_number: Some(8),
            },
            &mut verification_checks,
        );
        assert!(verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_runtime_line_edit_upconverted=true"
        }));
        assert!(verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_runtime_line_edit_source=raw_output"
        }));
    }

    #[test]
    fn patch_build_verify_runtime_patch_miss_repair_recovers_full_write_from_patch_replace_block() {
        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x6e; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let mut verification_checks = Vec::new();
        let repair = attempt_patch_build_verify_runtime_patch_miss_repair(
            &state,
            &worker_state,
            session_id,
            "filesystem__patch",
            Some(
                "ERROR_CLASS=NoEffectAfterAction Patch failed for path_utils.py: search block not found in file.",
            ),
            r#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","search":"return raw_path.strip().replace(\"\\\\\", \"/\")","replace":"return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"}}"#,
            &mut verification_checks,
        )
        .expect("repair should be synthesized");

        match repair {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("replace(\"//\", \"/\")"));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(verification_checks.iter().any(|check| {
            check == "runtime_patch_miss_repair_deterministic_recovery=full_write"
        }));
    }

    #[test]
    fn patch_build_verify_runtime_patch_miss_repair_recovers_full_write_from_retained_trace_payload(
    ) {
        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x74; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let mut verification_checks = Vec::new();
        let repair = attempt_patch_build_verify_runtime_patch_miss_repair(
            &state,
            &worker_state,
            session_id,
            "filesystem__patch",
            Some(
                "ERROR_CLASS=NoEffectAfterAction Patch failed for path_utils.py: search block not found in file.",
            ),
            r#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","replace":"return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")","search":"return raw_path.strip().replace\\(\\\", \\/\\).replace\\(\\/\\/\\, \\/\\).lstrip\\(\\.\\/\\)"}}"#,
            &mut verification_checks,
        )
        .expect("repair should be synthesized");

        match repair {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("prefix = \"./\""),
                    "content was: {content}"
                );
                assert!(
                    !content.contains("lstrip(\"./\")"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(verification_checks.iter().any(|check| {
            check
                == "runtime_patch_miss_repair_deterministic_recovery=goal_constrained_snapshot_write"
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_post_command_edit_rewrites_goal_violating_direct_patch_before_execution(
    ) {
        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x83; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let tool = AgentTool::FsPatch {
            path: path_utils.to_string_lossy().to_string(),
            replace:
                "def normalize_fixture_path(path): return path.replace('\\\\', '/').replace('//', '/').lstrip('./')"
                    .to_string(),
            search:
                "def normalize_fixture_path(path): return path.replace('\\\\', '/').replace('//', '/).lstrip('./'"
                    .to_string(),
        };
        let mut verification_checks = Vec::new();

        let rewritten = super::maybe_rewrite_patch_build_verify_post_command_edit(
            &state,
            &worker_state,
            session_id,
            &tool,
            &mut verification_checks,
        )
        .await
        .expect("rewrite check should succeed")
        .expect("expected direct patch rewrite");

        match rewritten {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, path_utils.to_string_lossy());
                assert_eq!(line_number, None);
                assert!(
                    content.contains("def normalize_fixture_path(raw_path: str) -> str"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("prefix = \"./\""),
                    "content was: {content}"
                );
                assert!(
                    !content.contains("lstrip(\"./\")"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(verification_checks
            .iter()
            .any(|check| { check == "patch_build_verify_direct_edit_projection_missing=true" }));
        assert!(verification_checks
            .iter()
            .any(|check| { check == "patch_build_verify_direct_edit_rewritten=true" }));
        assert!(verification_checks.iter().any(|check| {
            check == "patch_build_verify_direct_edit_rewrite_source=goal_constrained_snapshot"
        }));
    }

    #[test]
    fn patch_build_verify_primary_patch_file_prefers_explicit_absolute_path_from_raw_output() {
        let assignment = patch_assignment();
        let explicit_path = "/tmp/ioi-coding-fixture-123/path-normalizer-fixture/path_utils.py";
        let raw_tool_output = format!(
            r#"{{"name":"filesystem__patch","arguments":{{"path":"{explicit_path}","search":"return raw_path.strip().replace(\"\\\\\", \"/\")","replace":"return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"}}}}"#
        );

        let selected = super::patch_build_verify_primary_patch_file(&assignment, &raw_tool_output)
            .expect("expected target path");

        assert_eq!(selected, explicit_path);
    }

    #[test]
    fn patch_build_verify_runtime_patch_miss_repair_uses_explicit_absolute_path_when_cwd_differs() {
        let repo = tempdir().expect("tempdir should succeed");
        let unrelated = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x7a; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = unrelated.path().to_string_lossy().to_string();
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let mut verification_checks = Vec::new();
        let repair = attempt_patch_build_verify_runtime_patch_miss_repair(
            &state,
            &worker_state,
            session_id,
            "filesystem__patch",
            Some(
                "ERROR_CLASS=NoEffectAfterAction Patch failed for path_utils.py: search block not found in file.",
            ),
            format!(
                r#"{{"name":"filesystem__patch","arguments":{{"path":"{}","replace":"return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")","search":"return raw_path.strip().replace\\(\\\", \\/\\).replace\\(\\/\\/\\, \\/\\).lstrip\\(\\.\\/\\)"}}}}"#,
                path_utils.display()
            )
            .as_str(),
            &mut verification_checks,
        )
        .expect("repair should be synthesized");

        match repair {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, path_utils.to_string_lossy());
                assert_eq!(line_number, None);
                assert!(content.contains("replace(\"//\", \"/\")"));
                assert!(content.contains("lstrip(\"./\")"));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(verification_checks.iter().any(|check| {
            check == "runtime_patch_miss_repair_deterministic_recovery=full_write"
        }));
    }

    #[test]
    fn updated_python_block_candidate_expands_inline_function_against_single_line_current_block() {
        let current_block = concat!(
            "def normalize_fixture_path(raw_path: str) -> str: ",
            "return raw_path.strip().replace(\"\\\\\", \"/\")"
        );

        let updated_block = updated_python_block_candidate_from_raw_output(
            current_block,
            concat!(
                "The corrected implementation is ",
                "normalize_fixture_path(raw_path: str) -> str: ",
                "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
                "return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"
            ),
        )
        .expect("inline function candidate should be recovered");

        assert!(updated_block.starts_with("def normalize_fixture_path"));
        assert!(updated_block.contains("\n    \"\"\"Normalize a repo-relative path"));
        assert!(updated_block.contains(
            "\n    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_falls_back_to_full_write_without_patch_tool() {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x67; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_allowed_tools(vec![
                "filesystem__write_file",
                "filesystem__edit_line",
                "sys__exec_session",
                "agent__complete",
            ]),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "Current implementation:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.strip().replace(\"\\\\\", \"/\")\n",
                "```\n\n",
                "Updated implementation:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"/\").lstrip(\"./\")\n",
                "```\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("replace(\"//\", \"/\")"));
                assert!(content.contains("lstrip(\"./\")"));
                assert!(!content.contains("strip().replace(\"\\\\\", \"/\")"));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=code_block_write"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_prefers_runtime_edit_after_command_failure() {
        let fast_runtime = Arc::new(RepairRecordingRuntime::default());
        fast_runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Err(VmError::HostError("fast repair refused".to_string())));
        let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
        reasoning_runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
                    .to_vec(),
            ));
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            fast_runtime.clone(),
            reasoning_runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x69; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "Updated implementation:\n\n",
                "```python\n",
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"/\").lstrip(\"./\")\n",
                "```\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("prefix = \"./\""),
                    "content was: {content}"
                );
                assert!(
                    !content.contains("lstrip(\"./\")"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
        }));
        assert_eq!(
            fast_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
        assert_eq!(
            reasoning_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_rejects_syntax_invalid_fast_runtime_write_before_reasoning(
    ) {
        let fast_runtime = Arc::new(RepairRecordingRuntime::default());
        fast_runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./)\n"}}"#
                    .to_vec(),
            ));
        let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
        reasoning_runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
                    .to_vec(),
            ));
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            fast_runtime.clone(),
            reasoning_runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x6a; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "I will fix the malformed tool call by updating path_utils.py after the failing tests.",
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("prefix = \"./\""),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
        }));
        assert!(fast_runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .is_empty());
        assert_eq!(
            reasoning_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[test]
    fn patch_build_verify_runtime_goal_constraints_reject_prefix_stripping_single_pass_collapse() {
        let assignment = patch_assignment_with_path_parity_goal();
        let content = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"/\").lstrip(\"./\")\n"
        );
        let mut verification_checks = Vec::new();

        let failure = super::validate_patch_build_verify_runtime_goal_constraints(
            &assignment,
            content,
            &mut verification_checks,
            "invalid_tool_call_repair",
            "fast",
        );

        assert_eq!(failure.as_deref(), Some("fast:goal_path_prefix_violation"));
        assert!(verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_runtime_fast_goal_path_prefix_violation=true"
        }));
    }

    #[test]
    fn patch_build_verify_runtime_goal_constraints_reject_reverse_separator_direction() {
        let assignment = patch_assignment_with_path_parity_goal();
        let content = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    prefix = \"\"\n",
            "    if raw_path.startswith(\"./\"):\n",
            "        prefix = \"./\"\n",
            "        raw_path = raw_path[2:]\n",
            "    elif raw_path.startswith(\"/\"):\n",
            "        prefix = \"/\"\n",
            "        raw_path = raw_path[1:]\n",
            "    normalized = raw_path.replace(\"/\", \"\\\\\")\n",
            "    while \"\\\\\" in normalized:\n",
            "        normalized = normalized.replace(\"\\\\\", \"\\\\\")\n",
            "    return prefix + normalized\n"
        );
        let mut verification_checks = Vec::new();

        let failure = super::validate_patch_build_verify_runtime_goal_constraints(
            &assignment,
            content,
            &mut verification_checks,
            "invalid_tool_call_repair",
            "fast",
        );

        assert_eq!(
            failure.as_deref(),
            Some("fast:goal_separator_direction_violation")
        );
        assert!(verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_runtime_fast_goal_separator_direction_violation=true"
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_runtime_edit_repair_rejects_out_of_range_line_edit_after_command_failure(
    ) {
        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        fs::write(
            &path_utils,
            concat!(
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
            ),
        )
        .expect("write fixture source");

        let mut worker_state = build_worker_state([0x73; 32]);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);

        let repaired_tool = AgentTool::FsWrite {
            path: "path_utils.py".to_string(),
            content: "return raw_path.replace(\"\\\\\", \"/\")".to_string(),
            line_number: Some(12),
        };
        let mut verification_checks = Vec::new();

        let failure = super::validate_patch_build_verify_runtime_edit_repair(
            &worker_state,
            Some(&patch_assignment()),
            "I will update the function using filesystem__edit_line.",
            &repaired_tool,
            &mut verification_checks,
            "invalid_tool_call_repair",
            "fast_retry",
        )
        .await
        .expect("validation should succeed");

        assert_eq!(
            failure.as_deref(),
            Some("fast_retry:line_number_out_of_range")
        );
        assert!(verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_runtime_fast_retry_line_number_out_of_range=true"
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_runtime_edit_repair_rejects_line_edit_without_python_context_after_command_failure(
    ) {
        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        fs::write(
            &path_utils,
            "return raw_path.strip().replace('\\\\', '/').replace('//', '/').strip()\n",
        )
        .expect("write corrupted fixture source");

        let mut worker_state = build_worker_state([0x74; 32]);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);

        let repaired_tool = AgentTool::FsWrite {
            path: "path_utils.py".to_string(),
            content: "return raw_path.strip().replace('\\\\', '/').replace('//', '/').strip()"
                .to_string(),
            line_number: Some(1),
        };
        let mut verification_checks = Vec::new();

        let failure = super::validate_patch_build_verify_runtime_edit_repair(
            &worker_state,
            Some(&patch_assignment()),
            "I will rerun the focused verification command now.",
            &repaired_tool,
            &mut verification_checks,
            "invalid_tool_call_repair",
            "fast_retry",
        )
        .await
        .expect("validation should succeed");

        assert_eq!(
            failure.as_deref(),
            Some("fast_retry:line_edit_missing_python_context")
        );
        assert!(verification_checks.iter().any(|check| {
            check
                == "invalid_tool_call_repair_runtime_fast_retry_line_edit_missing_python_context=true"
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_runtime_edit_repair_rejects_multiline_line_edit_after_command_failure(
    ) {
        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        fs::write(
            &path_utils,
            concat!(
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
            ),
        )
        .expect("write fixture source");

        let mut worker_state = build_worker_state([0x75; 32]);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);

        let repaired_tool = AgentTool::FsWrite {
            path: "path_utils.py".to_string(),
            content: concat!(
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    prefix = \"\"\n",
                "    return prefix + raw_path.replace(\"\\\\\", \"/\")\n"
            )
            .to_string(),
            line_number: Some(1),
        };
        let mut verification_checks = Vec::new();

        let failure = super::validate_patch_build_verify_runtime_edit_repair(
            &worker_state,
            Some(&patch_assignment()),
            "I will update the function before rerunning tests.",
            &repaired_tool,
            &mut verification_checks,
            "invalid_tool_call_repair",
            "fast_retry",
        )
        .await
        .expect("validation should succeed");

        assert_eq!(
            failure.as_deref(),
            Some("fast_retry:line_edit_requires_full_write")
        );
        assert!(verification_checks.iter().any(|check| {
            check
                == "invalid_tool_call_repair_runtime_fast_retry_line_edit_requires_full_write=true"
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_retries_same_runtime_with_edit_only_tools_after_post_command_reread_rejection(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__read_file","arguments":{"path":"path_utils.py"}}"#
                    .to_vec(),
            ));
        runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
                    .to_vec(),
            ));
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x6b; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        mark_execution_receipt_with_value(
            &mut worker_state.tool_execution_log,
            "workspace_read_observed",
            "step=2;tool=filesystem__read_file;path=path_utils.py".to_string(),
        );
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "portun normalize_fixture_path(raw_path: str) -> str: ",
                "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
                "return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n\n",
                "I will use `filesystem__edit_line` to update the `normalize_fixture_path` ",
                "function in `path_utils.py` as described. This approach ensures that ",
                "backslashes are converted to forward slashes, duplicate separators are ",
                "collapsed, and leading `./` or `/` is preserved.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("prefix = \"./\""),
                    "content was: {content}"
                );
                assert!(
                    !content.contains("lstrip(\"./\")"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[test]
    fn patch_build_verify_redundant_refresh_read_rewrites_post_command_reread_to_goal_snapshot_write(
    ) {
        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x81; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        mark_execution_receipt_with_value(
            &mut worker_state.tool_execution_log,
            "workspace_read_observed",
            format!(
                "step=3;tool=filesystem__read_file;path={}",
                path_utils.display()
            ),
        );
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let mut verification_checks = Vec::new();
        let rewritten = maybe_rewrite_patch_build_verify_redundant_refresh_read(
            &state,
            &worker_state,
            session_id,
            &AgentTool::FsRead {
                path: path_utils.to_string_lossy().to_string(),
            },
            &mut verification_checks,
        )
        .expect("expected redundant reread rewrite");

        match rewritten {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, path_utils.to_string_lossy());
                assert_eq!(line_number, None);
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("prefix = \"./\""),
                    "content was: {content}"
                );
                assert!(
                    !content.contains("lstrip(\"./\")"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }

        assert!(verification_checks
            .iter()
            .any(|check| { check == "patch_build_verify_redundant_refresh_read_rewritten=true" }));
        assert!(verification_checks.iter().any(|check| {
            check
                == "patch_build_verify_redundant_refresh_read_rewrite_source=goal_constrained_snapshot"
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patch_build_verify_invalid_tool_repair_retries_same_runtime_with_edit_only_tools_after_runtime_failure(
    ) {
        let runtime = Arc::new(RepairRecordingRuntime::default());
        runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Err(VmError::HostError(
                "simulated runtime failure".to_string(),
            )));
        runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
                    .to_vec(),
            ));
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x6d; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        mark_execution_receipt_with_value(
            &mut worker_state.tool_execution_log,
            "workspace_read_observed",
            "step=2;tool=filesystem__read_file;path=path_utils.py".to_string(),
        );
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            concat!(
                "portun normalize_fixture_path(raw_path: str) -> str: ",
                "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
                "return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n\n",
                "I will use `filesystem__edit_line` to update the `normalize_fixture_path` ",
                "function in `path_utils.py` as described.\n"
            ),
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(
                    content.contains("while \"//\" in normalized"),
                    "content was: {content}"
                );
                assert!(
                    content.contains("prefix = \"./\""),
                    "content was: {content}"
                );
                assert!(
                    !content.contains("lstrip(\"./\")"),
                    "content was: {content}"
                );
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
        }));
        assert_eq!(
            runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_tool_repair_prefers_fast_runtime_before_reasoning() {
        let fast_runtime = Arc::new(RepairRecordingRuntime::default());
        fast_runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","search":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path","replace":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path.strip().replace(\"\\\\\", \"/\")"}}"#
                    .to_vec(),
            ));
        let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            fast_runtime.clone(),
            reasoning_runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x33; 32];
        let key = get_state_key(&session_id);
        let worker_state = build_worker_state(session_id);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let mut worker_state = worker_state;
        worker_state
            .command_history
            .push_back(crate::agentic::desktop::types::CommandExecution {
                command: "python3 -m unittest tests.test_path_utils -v".to_string(),
                exit_code: 1,
                stdout: String::new(),
                stderr: String::new(),
                timestamp_ms: 1,
                step_index: 0,
            });
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode updated worker state"),
            )
            .expect("update worker state");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "portun normalize_fixture_path(raw_path: str) -> str: return raw_path.strip().replace(\"\\\\\", \"/\")",
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        assert_eq!(
            repair
                .repaired_tool
                .expect("expected repaired tool")
                .name_string(),
            "filesystem__patch"
        );
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "invalid_tool_call_repair_runtime=fast"));
        assert_eq!(
            fast_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            1
        );
        assert_eq!(
            reasoning_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refusal_repair_synthesizes_targeted_exec_before_pause() {
        let fast_runtime = Arc::new(RepairRecordingRuntime::default());
        let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            fast_runtime.clone(),
            reasoning_runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x66; 32];
        let key = get_state_key(&session_id);
        let worker_state = build_worker_state(session_id);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let repair = attempt_refusal_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "Empty content (reason: stop)",
        )
        .await
        .expect("refusal repair should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::SysExecSession {
                command,
                args,
                stdin,
            } => {
                assert_eq!(command, "bash");
                assert_eq!(
                    args,
                    vec![
                        "-lc".to_string(),
                        "python3 -m unittest tests.test_path_utils -v".to_string()
                    ]
                );
                assert_eq!(stdin, None);
            }
            other => panic!("expected sys__exec_session, got {:?}", other),
        }
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "refusal_repair_succeeded=true"));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=refusal_empty_content"
        }));
        assert_eq!(
            fast_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
        assert_eq!(
            reasoning_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refusal_repair_bootstraps_targeted_exec_on_initial_empty_stop() {
        let fast_runtime = Arc::new(RepairRecordingRuntime::default());
        let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            fast_runtime.clone(),
            reasoning_runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x69; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.recent_actions.clear();
        worker_state.consecutive_failures = 0;
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let repair = attempt_refusal_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "Empty content (reason: stop)",
        )
        .await
        .expect("refusal repair should succeed");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::SysExecSession {
                command,
                args,
                stdin,
            } => {
                assert_eq!(command, "bash");
                assert_eq!(
                    args,
                    vec![
                        "-lc".to_string(),
                        "python3 -m unittest tests.test_path_utils -v".to_string()
                    ]
                );
                assert_eq!(stdin, None);
            }
            other => panic!("expected sys__exec_session, got {:?}", other),
        }
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "refusal_repair_succeeded=true"));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=refusal_empty_content_bootstrap"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_targeted_command_bootstrap=initial"
        }));
        assert_eq!(
            fast_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
        assert_eq!(
            reasoning_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refusal_repair_does_not_replay_targeted_exec_after_command_history() {
        let fast_runtime = Arc::new(RepairRecordingRuntime::default());
        let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            fast_runtime,
            reasoning_runtime,
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x67; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            stdout: String::new(),
            stderr: "FAIL".to_string(),
            exit_code: 1,
            timestamp_ms: 1,
            step_index: 0,
        });
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let repair = attempt_refusal_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "Empty content (reason: stop)",
        )
        .await
        .expect("refusal repair should complete");

        assert!(repair.repaired_tool.is_none());
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "refusal_repair_skipped=no_deterministic_followup"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refusal_repair_uses_goal_snapshot_write_after_command_failure() {
        let fast_runtime = Arc::new(RepairRecordingRuntime::default());
        let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            fast_runtime.clone(),
            reasoning_runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x6a; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(
            &mut state,
            session_id,
            &patch_assignment_with_path_parity_goal(),
        )
        .expect("persist worker assignment");

        let repair = attempt_refusal_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "Empty content (reason: stop)",
        )
        .await
        .expect("refusal repair should complete");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("while \"//\" in normalized"));
                assert!(content.contains("prefix = \"./\""));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "refusal_repair_succeeded=true"));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "refusal_repair_runtime=deterministic"));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
        }));
        assert!(repair.verification_checks.iter().any(|check| {
            check
                == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
        }));
        assert_eq!(
            fast_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
        assert_eq!(
            reasoning_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refusal_repair_recovers_edit_tool_after_command_failure() {
        let fast_runtime = Arc::new(RepairRecordingRuntime::default());
        let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
        reasoning_runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
                    .to_vec(),
            ));
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            fast_runtime.clone(),
            reasoning_runtime.clone(),
        );

        let repo = tempdir().expect("tempdir should succeed");
        let path_utils = repo.path().join("path_utils.py");
        let original = concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        );
        fs::write(&path_utils, original).expect("write fixture source");

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x68; 32];
        let key = get_state_key(&session_id);
        let mut worker_state = build_worker_state(session_id);
        worker_state.working_directory = repo.path().to_string_lossy().to_string();
        worker_state.recent_actions = vec![
            "attempt::NoEffectAfterAction::first".to_string(),
            "attempt::UnexpectedState::second".to_string(),
        ];
        record_targeted_check_failure(&mut worker_state);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let repair = attempt_refusal_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "Empty content (reason: stop)",
        )
        .await
        .expect("refusal repair should complete");

        match repair.repaired_tool.expect("expected repaired tool") {
            AgentTool::FsWrite {
                path,
                content,
                line_number,
            } => {
                assert_eq!(path, "path_utils.py");
                assert_eq!(line_number, None);
                assert!(content.contains("while \"//\" in normalized"));
                assert!(content.contains("prefix = \"./\""));
            }
            other => panic!("expected filesystem__write_file, got {:?}", other),
        }
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "refusal_repair_succeeded=true"));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "refusal_repair_runtime=reasoning"));
        assert!(repair.verification_checks.iter().any(|check| {
            check == "refusal_repair_patch_tool_suppressed_after_command_failure=true"
        }));
        let fast_seen_tools = fast_runtime
            .seen_tools
            .lock()
            .expect("seen_tools mutex poisoned");
        assert_eq!(fast_seen_tools.len(), 1);
        assert!(!fast_seen_tools[0]
            .iter()
            .any(|tool_name| tool_name == "filesystem__patch"));
        let seen_tools = reasoning_runtime
            .seen_tools
            .lock()
            .expect("seen_tools mutex poisoned");
        assert_eq!(seen_tools.len(), 1);
        assert!(!seen_tools[0]
            .iter()
            .any(|tool_name| tool_name == "sys__exec_session"));
        assert!(!seen_tools[0]
            .iter()
            .any(|tool_name| tool_name == "filesystem__patch"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_tool_repair_falls_back_to_reasoning_after_fast_error() {
        let fast_runtime = Arc::new(RepairRecordingRuntime::default());
        fast_runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Err(VmError::HostError(
                "LLM_REFUSAL: Empty content (reason: stop)".to_string(),
            )));
        let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
        reasoning_runtime
            .outputs
            .lock()
            .expect("outputs mutex poisoned")
            .push(Ok(
                br#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","search":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path","replace":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path.strip().replace(\"\\\\\", \"/\")"}}"#
                    .to_vec(),
            ));
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = DesktopAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            fast_runtime.clone(),
            reasoning_runtime.clone(),
        );

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let session_id = [0x44; 32];
        let key = get_state_key(&session_id);
        let worker_state = build_worker_state(session_id);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        persist_worker_assignment(&mut state, session_id, &patch_assignment())
            .expect("persist worker assignment");

        let repair = attempt_invalid_tool_call_repair(
            &service,
            &mut state,
            &worker_state,
            session_id,
            "portun normalize_fixture_path(raw_path: str) -> str: return raw_path.strip().replace(\"\\\\\", \"/\")",
            "JSON Syntax Error: expected value at line 1 column 1",
        )
        .await
        .expect("repair attempt should succeed");

        assert_eq!(
            repair
                .repaired_tool
                .expect("expected repaired tool")
                .name_string(),
            "filesystem__patch"
        );
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "invalid_tool_call_repair_runtime_fallback=true"));
        assert!(repair
            .verification_checks
            .iter()
            .any(|check| check == "invalid_tool_call_repair_runtime=reasoning"));
        assert_eq!(
            fast_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            1
        );
        assert_eq!(
            reasoning_runtime
                .seen_inputs
                .lock()
                .expect("seen_inputs mutex poisoned")
                .len(),
            1
        );
    }
}
