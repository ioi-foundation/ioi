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
use crate::agentic::desktop::worker_context::{
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

enum DeterministicEditRepairValidation {
    Accepted(AgentTool),
    Rejected(String),
}

#[path = "repair/core.rs"]
mod core;
#[path = "repair/patch_build_verify.rs"]
mod patch_build_verify;
#[path = "repair/python_block.rs"]
mod python_block;
#[path = "repair/prompt_context.rs"]
mod prompt_context;

pub(crate) use core::{attempt_invalid_tool_call_repair, attempt_refusal_repair};
pub(crate) use patch_build_verify::{
    attempt_patch_build_verify_runtime_patch_miss_repair,
    maybe_rewrite_patch_build_verify_post_command_edit,
    maybe_rewrite_patch_build_verify_post_success_completion,
    maybe_rewrite_patch_build_verify_redundant_refresh_read,
};
use python_block::{
    align_python_block_to_reference, extract_fenced_python_function_blocks,
    extract_primary_python_function_block,
    inline_python_block_repair_candidate_from_line, matches_python_function_signature,
    normalize_block_for_match, normalize_code_block_content,
    patch_build_verify_path_parity_reference_repair,
    patch_build_verify_runtime_repair_preserves_python_signature, patch_search_block,
    python_blocks_reference_same_function, updated_python_block_candidate_from_raw_output,
    validate_python_module_syntax,
};
use prompt_context::{
    build_invalid_tool_repair_prompt, build_invalid_tool_repair_retry_prompt,
    build_refusal_repair_prompt, command_history_contains_goal_command,
    first_goal_command_literal, goal_command_retry_ready_after_workspace_edit,
    latest_command_failure_summary, latest_goal_command, latest_workspace_edit_step,
    latest_workspace_read_step,
    patch_build_verify_completion_ready, patch_build_verify_current_file_snapshot,
    patch_build_verify_explicit_target_path, patch_build_verify_primary_patch_file,
    patch_build_verify_refresh_read_ready, raw_tool_output_requests_refresh_read,
    synthesize_patch_build_verify_completion_result,
};

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
        && patch_build_verify_current_file_snapshot(agent_state, assignment, &assignment.goal)
            .is_some()
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
        ImageEditRequest, ImageGenerationRequest, ImageGenerationResult, InferenceRuntime,
        RerankRequest, RerankResult, SpeechSynthesisRequest, SpeechSynthesisResult,
        TextGenerationRequest, TextGenerationResult, TranscriptionRequest,
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
                .unwrap_or_else(|| {
                    panic!(
                        "expected repaired tool; checks={:?}",
                        repair.verification_checks
                    )
                })
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
                .unwrap_or_else(|| {
                    panic!(
                        "expected repaired tool; checks={:?}",
                        repair.verification_checks
                    )
                })
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
