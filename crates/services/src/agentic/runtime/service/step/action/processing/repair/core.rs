use super::*;
use crate::agentic::runtime::service::step::route_projection::project_route_decision;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::InferenceOptions;

const CONVERSATION_REFUSAL_REPAIR_TIMEOUT_SECS: u64 = 8;
const CONVERSATION_REFUSAL_REPAIR_LOCAL_GPU_TIMEOUT_SECS: u64 = 60;

fn env_var_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn conversation_refusal_repair_timeout() -> Duration {
    let default_timeout_secs = if env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV") {
        CONVERSATION_REFUSAL_REPAIR_LOCAL_GPU_TIMEOUT_SECS
    } else {
        CONVERSATION_REFUSAL_REPAIR_TIMEOUT_SECS
    };

    std::env::var("IOI_CONVERSATION_REFUSAL_REPAIR_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(default_timeout_secs))
}

fn recent_conversation_excerpt(messages: &[ioi_types::app::agentic::ChatMessage]) -> String {
    messages
        .iter()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|message| {
            format!(
                "{}: {}",
                message.role,
                truncate_for_prompt(message.content.trim(), 500)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn latest_user_message_for_refusal_repair(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    agent_state: &AgentState,
) -> (String, Option<String>) {
    let history = service.hydrate_session_history(session_id).ok();
    let latest_user = history
        .as_ref()
        .and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|message| message.role.trim().eq_ignore_ascii_case("user"))
                .map(|message| message.content.trim().to_string())
        })
        .filter(|content| !content.is_empty())
        .unwrap_or_else(|| agent_state.goal.trim().to_string());
    let recent_excerpt = history
        .as_ref()
        .map(|messages| recent_conversation_excerpt(messages))
        .filter(|excerpt| !excerpt.trim().is_empty());
    (latest_user, recent_excerpt)
}

fn build_direct_inline_refusal_repair_prompt(
    latest_user_message: &str,
    recent_conversation: Option<&str>,
    refusal_reason: &str,
) -> String {
    let mut prompt = String::from(
        "You are recovering a failed direct-inline answer for the IOI desktop agent.\n\
Return ONLY the final user-facing answer text.\n\
Rules:\n\
1. Do not output JSON, tool names, markdown fences, or process narration.\n\
2. Do not mention recovery, refusals, routing, or internal tooling.\n\
3. Answer the user's latest request directly and concisely.\n\
4. If the request would require fresh current data, exact live state, or unavailable private data, say that fresh retrieval is required and do not guess.\n\
5. Keep the answer useful on its own.\n",
    );
    prompt.push_str("\nRefusal context:\n");
    prompt.push_str(&truncate_for_prompt(refusal_reason.trim(), 300));
    if let Some(recent_conversation) = recent_conversation {
        prompt.push_str("\nRecent conversation:\n");
        prompt.push_str(&truncate_for_prompt(recent_conversation.trim(), 1800));
    }
    prompt.push_str("\nLatest user request:\n");
    prompt.push_str(&truncate_for_prompt(latest_user_message.trim(), 1500));
    prompt.push_str("\nFinal answer text:");
    prompt
}

fn normalize_direct_inline_repair_message(raw_output: &str) -> Option<String> {
    let trimmed = raw_output.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let extracted = value
            .as_str()
            .map(str::trim)
            .or_else(|| {
                value
                    .get("message")
                    .and_then(|value| value.as_str())
                    .map(str::trim)
            })
            .or_else(|| {
                value
                    .get("arguments")
                    .and_then(|arguments| arguments.get("message"))
                    .and_then(|value| value.as_str())
                    .map(str::trim)
            })
            .filter(|value| !value.is_empty());
        if let Some(message) = extracted {
            return Some(message.to_string());
        }
    }

    Some(trimmed.to_string())
}

async fn run_direct_inline_refusal_repair_inference(
    service: &RuntimeAgentService,
    runtime: Arc<dyn InferenceRuntime>,
    runtime_label: &str,
    session_id: [u8; 32],
    prompt: &str,
    verification_checks: &mut Vec<String>,
) -> Result<Option<String>, TransactionError> {
    verification_checks.push(format!(
        "refusal_repair_direct_inline_runtime_attempt={runtime_label}"
    ));

    let messages = json!([
        { "role": "system", "content": prompt },
        { "role": "user", "content": "Answer the latest user request now." }
    ]);
    let input = serde_json::to_vec(&messages)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let inference_input = service
        .prepare_cloud_inference_input(
            Some(session_id),
            "desktop_agent",
            INVALID_TOOL_REPAIR_MODEL_ID,
            &input,
        )
        .await?;
    let timeout = conversation_refusal_repair_timeout();
    let output = match tokio::time::timeout(
        timeout,
        runtime.execute_inference(
            [0u8; 32],
            &inference_input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: false,
                max_tokens: 512,
                ..Default::default()
            },
        ),
    )
    .await
    {
        Err(_) => {
            verification_checks.push(format!(
                "refusal_repair_direct_inline_runtime_{runtime_label}_timeout=true"
            ));
            return Ok(None);
        }
        Ok(Err(error)) => {
            verification_checks.push(format!(
                "refusal_repair_direct_inline_runtime_{runtime_label}_error={}",
                sanitize_check_value(&error.to_string())
            ));
            return Ok(None);
        }
        Ok(Ok(bytes)) => String::from_utf8_lossy(&bytes).to_string(),
    };

    let Some(message) = normalize_direct_inline_repair_message(&output) else {
        verification_checks.push(format!(
            "refusal_repair_direct_inline_runtime_{runtime_label}_empty_output=true"
        ));
        return Ok(None);
    };

    verification_checks.push(format!(
        "refusal_repair_direct_inline_runtime_{runtime_label}_succeeded=true"
    ));
    Ok(Some(message))
}

async fn attempt_direct_inline_refusal_chat_reply_repair(
    service: &RuntimeAgentService,
    agent_state: &AgentState,
    session_id: [u8; 32],
    refusal_reason: &str,
    verification_checks: &mut Vec<String>,
) -> Result<Option<AgentTool>, TransactionError> {
    let (latest_user_message, recent_conversation) =
        latest_user_message_for_refusal_repair(service, session_id, agent_state);
    if latest_user_message.trim().is_empty() {
        verification_checks
            .push("refusal_repair_direct_inline_skipped=missing_latest_user_message".to_string());
        return Ok(None);
    }

    let prompt = build_direct_inline_refusal_repair_prompt(
        &latest_user_message,
        recent_conversation.as_deref(),
        refusal_reason,
    );
    verification_checks.push("refusal_repair_direct_inline_attempted=true".to_string());
    if let Some(message) = run_direct_inline_refusal_repair_inference(
        service,
        service.fast_inference.clone(),
        "fast",
        session_id,
        &prompt,
        verification_checks,
    )
    .await?
    {
        verification_checks.push("refusal_repair_direct_inline_succeeded=true".to_string());
        return Ok(Some(AgentTool::ChatReply { message }));
    }

    if !Arc::ptr_eq(&service.fast_inference, &service.reasoning_inference) {
        if let Some(message) = run_direct_inline_refusal_repair_inference(
            service,
            service.reasoning_inference.clone(),
            "reasoning",
            session_id,
            &prompt,
            verification_checks,
        )
        .await?
        {
            verification_checks.push("refusal_repair_direct_inline_succeeded=true".to_string());
            return Ok(Some(AgentTool::ChatReply { message }));
        }
    }

    Ok(None)
}

pub(crate) async fn attempt_refusal_repair(
    service: &RuntimeAgentService,
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

    let route_decision = project_route_decision(
        service,
        state,
        agent_state,
        "system::refusal",
        agent_state.current_tier,
    )
    .await;
    if route_decision.direct_answer_allowed
        && route_decision
            .output_intent
            .eq_ignore_ascii_case("direct_inline")
        && route_decision.route_family.eq_ignore_ascii_case("general")
        && route_decision
            .effective_tool_surface
            .projected_tools
            .iter()
            .any(|tool_name| tool_name.eq_ignore_ascii_case("chat__reply"))
    {
        verification_checks.push("refusal_repair_route_direct_inline=true".to_string());
        if let Some(repaired_tool) = attempt_direct_inline_refusal_chat_reply_repair(
            service,
            agent_state,
            session_id,
            refusal_reason,
            &mut verification_checks,
        )
        .await?
        {
            verification_checks.push("refusal_repair_succeeded=true".to_string());
            verification_checks.push(format!(
                "refusal_repair_tool={}",
                repaired_tool.name_string()
            ));
            verification_checks
                .push("refusal_repair_runtime=conversation_direct_inline".to_string());
            return Ok(InvalidToolRepairAttempt {
                repaired_tool: Some(repaired_tool),
                verification_checks,
            });
        }
    } else {
        verification_checks.push("refusal_repair_route_direct_inline=false".to_string());
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

pub(crate) async fn attempt_invalid_tool_call_repair(
    service: &RuntimeAgentService,
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
