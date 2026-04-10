use super::*;

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
