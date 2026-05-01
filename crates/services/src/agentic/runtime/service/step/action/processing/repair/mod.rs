use crate::agentic::runtime::execution::filesystem::resolve_tool_path;
use crate::agentic::runtime::middleware;
use crate::agentic::runtime::service::lifecycle::load_worker_assignment;
use crate::agentic::runtime::service::step::action::execution_evidence_value;
use crate::agentic::runtime::service::step::anti_loop::{latest_failure_class, FailureClass};
use crate::agentic::runtime::service::step::worker::{
    filter_tools_for_worker_recovery, worker_recovery_failure_class,
};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::tools::discover_tools;
use crate::agentic::runtime::types::{AgentState, ToolCallStatus, WorkerAssignment};
use crate::agentic::runtime::worker_context::{
    collect_goal_literals, extract_worker_context_field, matches_command_literal,
    normalize_whitespace, split_parent_playbook_context, CommandLiteralHeuristic,
};
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

pub(crate) fn repair_tool_names_match(left: &str, right: &str) -> bool {
    if left.trim().eq_ignore_ascii_case(right.trim()) {
        return true;
    }

    if repair_tool_alias(left) == repair_tool_alias(right) {
        return true;
    }

    match (
        middleware::canonical_deterministic_tool_name(left),
        middleware::canonical_deterministic_tool_name(right),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn repair_tool_alias(name: &str) -> String {
    match name.trim().to_ascii_lowercase().as_str() {
        "filesystem__write_file" | "file__write" => "file__write".to_string(),
        "filesystem__patch" | "file__edit" => "file__edit".to_string(),
        "filesystem__edit_line" | "file__replace_line" => "file__replace_line".to_string(),
        "filesystem__read_file" | "file__read" | "file__view" => "file__read".to_string(),
        "filesystem__search" | "file__search" => "file__search".to_string(),
        "filesystem__list_directory" | "filesystem__list_dir" | "file__list" => {
            "file__list".to_string()
        }
        "filesystem__stat" | "file__info" => "file__info".to_string(),
        "sys__exec_session" | "shell__run" => "shell__run".to_string(),
        "system__fail" | "agent__escalate" => "agent__escalate".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn repair_allowed_tool_names_include(
    allowed_tool_names: &BTreeSet<String>,
    candidate: &str,
) -> bool {
    allowed_tool_names
        .iter()
        .any(|allowed| repair_tool_names_match(allowed, candidate))
}

enum DeterministicEditRepairValidation {
    Accepted(AgentTool),
    Rejected(String),
}

mod core;
mod deterministic;
mod patch_build_verify;
mod prompt_context;
mod python_block;
mod validation;

pub(crate) use core::{attempt_invalid_tool_call_repair, attempt_refusal_repair};
use deterministic::*;
pub(crate) use patch_build_verify::{
    attempt_patch_build_verify_runtime_patch_miss_repair,
    maybe_rewrite_patch_build_verify_post_command_edit,
    maybe_rewrite_patch_build_verify_post_success_completion,
    maybe_rewrite_patch_build_verify_redundant_refresh_read,
};
use prompt_context::{
    build_invalid_tool_repair_prompt, build_invalid_tool_repair_retry_prompt,
    build_refusal_repair_prompt, command_history_contains_goal_command, first_goal_command_literal,
    goal_command_retry_ready_after_workspace_edit, latest_command_failure_summary,
    latest_goal_command, latest_workspace_edit_step, latest_workspace_read_step,
    patch_build_verify_completion_ready, patch_build_verify_current_file_snapshot,
    patch_build_verify_explicit_target_path, patch_build_verify_primary_patch_file,
    patch_build_verify_refresh_read_ready, raw_tool_output_requests_refresh_read,
    synthesize_patch_build_verify_completion_result,
};
use python_block::{
    align_python_block_to_reference, extract_fenced_python_function_blocks,
    extract_primary_python_function_block, inline_python_block_repair_candidate_from_line,
    matches_python_function_signature, normalize_block_for_match, normalize_code_block_content,
    patch_build_verify_path_parity_reference_repair,
    patch_build_verify_runtime_repair_preserves_python_signature, patch_search_block,
    python_blocks_reference_same_function, updated_python_block_candidate_from_raw_output,
    validate_python_module_syntax,
};
use validation::*;

struct RepairRuntimeAttempt {
    repaired_tool: Option<AgentTool>,
    failure_summary: Option<String>,
}

async fn attempt_invalid_tool_call_runtime_repair(
    service: &RuntimeAgentService,
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
    service: &RuntimeAgentService,
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
    service: &RuntimeAgentService,
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
    if ![
        "filesystem__patch",
        "filesystem__edit_line",
        "filesystem__write_file",
    ]
    .iter()
    .any(|tool_name| repair_allowed_tool_names_include(allowed_tool_names, tool_name))
    {
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
    service: &RuntimeAgentService,
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
    let repaired_tool = canonicalize_legacy_filesystem_edit_tool(repaired_tool);
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
    if !repair_allowed_tool_names_include(allowed_tool_names, &repaired_tool_name) {
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
    service: &RuntimeAgentService,
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

    let repaired_tool = canonicalize_legacy_filesystem_edit_tool(repaired_tool);
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

    if !repair_allowed_tool_names_include(allowed_tool_names, &repaired_tool.name_string()) {
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

#[cfg(test)]
mod tests;
