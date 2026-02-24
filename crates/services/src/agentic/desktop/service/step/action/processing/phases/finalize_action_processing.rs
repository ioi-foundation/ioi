    {
    if !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        if let Some(tool_jcs) = executed_tool_jcs.as_deref() {
            let resolved_retry_hash = retry_intent_hash
                .as_deref()
                .unwrap_or(intent_hash.as_str())
                .to_string();
            let incident_directive = advance_incident_after_action_outcome(
                service,
                state,
                agent_state,
                session_id,
                &resolved_retry_hash,
                tool_jcs,
                success,
                block_height,
                error_msg.as_deref(),
                &mut verification_checks,
            )
            .await?;
            if matches!(incident_directive, IncidentDirective::QueueActions) {
                remediation_queued = true;
                stop_condition_hit = false;
                escalation_path = None;
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Running;
            }
        }
    }

    if success && !is_gated {
        agent_state.recent_actions.clear();
    } else if !success && !awaiting_sudo_password && !awaiting_clarification {
        failure_class = classify_failure(error_msg.as_deref(), &policy_decision);
        if let Some(class) = failure_class {
            let target_id = agent_state.target.as_ref().and_then(|target| {
                target
                    .app_hint
                    .as_deref()
                    .filter(|v| !v.trim().is_empty())
                    .or_else(|| {
                        target
                            .title_pattern
                            .as_deref()
                            .filter(|v| !v.trim().is_empty())
                    })
            });
            let window_fingerprint = if final_visual_phash == [0u8; 32] {
                None
            } else {
                Some(hex::encode(final_visual_phash))
            };
            let retry_hash = retry_intent_hash.as_deref().unwrap_or(intent_hash.as_str());
            let attempt_key = build_attempt_key(
                retry_hash,
                routing_decision.tier,
                &current_tool_name,
                target_id,
                window_fingerprint.as_deref(),
            );
            let (repeat_count, attempt_key_hash) =
                register_failure_attempt(agent_state, class, &attempt_key);
            let budget_remaining = retry_budget_remaining(repeat_count);
            let blocked_without_change = should_block_retry_without_change(class, repeat_count);
            verification_checks.push(format!("attempt_repeat_count={}", repeat_count));
            verification_checks.push(format!("attempt_key_hash={}", attempt_key_hash));
            verification_checks.push(format!(
                "attempt_retry_budget_remaining={}",
                budget_remaining
            ));
            verification_checks.push(format!(
                "attempt_retry_blocked_without_change={}",
                blocked_without_change
            ));
            if should_fail_fast_web_timeout(
                agent_state.resolved_intent.as_ref(),
                &current_tool_name,
                class,
                agent_state.pending_search_completion.is_some(),
            ) {
                let summary = format!(
                    "Web retrieval timed out while executing '{}'. Retry later or narrow the query/sources.",
                    current_tool_name
                );
                stop_condition_hit = true;
                escalation_path = Some("web_timeout_fail_fast".to_string());
                is_lifecycle_action = true;
                remediation_queued = false;
                action_output = Some(summary.clone());
                agent_state.execution_queue.clear();
                agent_state.pending_search_completion = None;
                agent_state.status = AgentStatus::Completed(Some(summary));
                verification_checks.push("web_timeout_fail_fast=true".to_string());
            } else {
                let incident_state = load_incident_state(state, &session_id)?;
                if should_enter_incident_recovery(
                    Some(class),
                    &policy_decision,
                    stop_condition_hit,
                    incident_state.as_ref(),
                ) {
                    if let Some(root_tool_jcs) = executed_tool_jcs.as_deref() {
                        let (resolved_retry_hash, recovery_tool_name, recovery_tool_jcs): (
                            String,
                            String,
                            Vec<u8>,
                        ) = if let Some(existing) = incident_state.as_ref().filter(|i| i.active) {
                            (
                                existing.root_retry_hash.clone(),
                                existing.root_tool_name.clone(),
                                existing.root_tool_jcs.clone(),
                            )
                        } else {
                            (
                                retry_intent_hash
                                    .as_deref()
                                    .unwrap_or(intent_hash.as_str())
                                    .to_string(),
                                current_tool_name.clone(),
                                root_tool_jcs.to_vec(),
                            )
                        };
                        remediation_queued = matches!(
                            start_or_continue_incident_recovery(
                                service,
                                state,
                                agent_state,
                                session_id,
                                block_height,
                                &rules,
                                &resolved_retry_hash,
                                &recovery_tool_name,
                                &recovery_tool_jcs,
                                class,
                                error_msg.as_deref(),
                                &mut verification_checks,
                            )
                            .await?,
                            IncidentDirective::QueueActions
                        );
                    }
                }

                let install_lookup_failure = error_msg
                    .as_deref()
                    .map(|msg| requires_wait_for_clarification(&current_tool_name, msg))
                    .unwrap_or(false);

                if remediation_queued {
                    stop_condition_hit = false;
                    escalation_path = None;
                    is_lifecycle_action = true;
                    agent_state.status = AgentStatus::Running;
                } else if install_lookup_failure {
                    stop_condition_hit = true;
                    escalation_path = Some("wait_for_clarification".to_string());
                    is_lifecycle_action = true;
                    awaiting_clarification = true;
                    mark_incident_wait_for_user(
                        state,
                        session_id,
                        "wait_for_clarification",
                        FailureClass::UserInterventionNeeded,
                        error_msg.as_deref(),
                    )?;
                    agent_state.execution_queue.clear();
                    agent_state.status = AgentStatus::Paused(
                        "Waiting for clarification on target identity.".to_string(),
                    );
                } else if matches!(class, FailureClass::UserInterventionNeeded) {
                    stop_condition_hit = true;
                    escalation_path = Some(escalation_path_for_failure(class).to_string());
                    is_lifecycle_action = true;
                    agent_state.status = AgentStatus::Paused(
                        "Waiting for user intervention: complete the required human verification in your browser/app, then resume.".to_string(),
                    );
                } else if should_use_web_research_path(agent_state)
                    && matches!(class, FailureClass::UnexpectedState)
                {
                    // Keep web research autonomous under transient tool/schema instability.
                    stop_condition_hit = false;
                    escalation_path = None;
                    is_lifecycle_action = true;
                    success = true;
                    error_msg = None;
                    let note = format!(
                        "Transient unexpected state while executing '{}'; continuing web research.",
                        current_tool_name
                    );
                    history_entry = Some(note.clone());
                    action_output = Some(note);
                    agent_state.status = AgentStatus::Running;
                    agent_state.recent_actions.clear();
                    verification_checks.push("web_unexpected_retry_bypass=true".to_string());
                } else if blocked_without_change {
                    stop_condition_hit = true;
                    escalation_path = Some(escalation_path_for_failure(class).to_string());
                    is_lifecycle_action = true;
                    agent_state.status = AgentStatus::Paused(format!(
                        "Retry blocked: unchanged AttemptKey for {}",
                        class.as_str()
                    ));
                    if matches!(
                        class,
                        FailureClass::FocusMismatch
                            | FailureClass::TargetNotFound
                            | FailureClass::VisionTargetNotFound
                            | FailureClass::NoEffectAfterAction
                            | FailureClass::TierViolation
                            | FailureClass::MissingDependency
                            | FailureClass::ContextDrift
                            | FailureClass::ToolUnavailable
                            | FailureClass::NonDeterministicUI
                            | FailureClass::TimeoutOrHang
                            | FailureClass::UnexpectedState
                    ) {
                        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                    }
                } else if should_trip_retry_guard(class, repeat_count) {
                    stop_condition_hit = true;
                    escalation_path = Some(escalation_path_for_failure(class).to_string());
                    is_lifecycle_action = true;
                    agent_state.status = AgentStatus::Paused(format!(
                        "Retry guard tripped after repeated {} failures",
                        class.as_str()
                    ));
                    if matches!(
                        class,
                        FailureClass::FocusMismatch
                            | FailureClass::TargetNotFound
                            | FailureClass::VisionTargetNotFound
                            | FailureClass::NoEffectAfterAction
                            | FailureClass::TierViolation
                            | FailureClass::MissingDependency
                            | FailureClass::ContextDrift
                            | FailureClass::ToolUnavailable
                            | FailureClass::NonDeterministicUI
                            | FailureClass::TimeoutOrHang
                            | FailureClass::UnexpectedState
                    ) {
                        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                    }
                }
            }
        }
    }

    if !success
        && matches!(agent_state.status, AgentStatus::Paused(_))
        && !stop_condition_hit
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        stop_condition_hit = true;
        is_lifecycle_action = true;
        if escalation_path.is_none() {
            escalation_path = Some("wait_for_user".to_string());
        }
    }

    verification_checks.push(format!("policy_decision={}", policy_decision));
    verification_checks.push(format!("was_gated={}", is_gated));
    verification_checks.push(format!("awaiting_sudo_password={}", awaiting_sudo_password));
    verification_checks.push(format!("awaiting_clarification={}", awaiting_clarification));
    verification_checks.push(format!("remediation_queued={}", remediation_queued));
    verification_checks.push(format!("stop_condition_hit={}", stop_condition_hit));
    verification_checks.push(format!(
        "routing_tier_selected={}",
        tier_as_str(routing_decision.tier)
    ));
    verification_checks.push(format!(
        "routing_reason_code={}",
        routing_decision.reason_code
    ));
    verification_checks.push(format!(
        "routing_source_failure={}",
        routing_decision
            .source_failure
            .map(|class| class.as_str().to_string())
            .unwrap_or_else(|| "None".to_string())
    ));
    verification_checks.push(format!(
        "routing_tier_matches_pre_state={}",
        pre_state_summary.tier == tier_as_str(routing_decision.tier)
    ));
    if let Some(class) = failure_class {
        verification_checks.push(format!("failure_class={}", class.as_str()));
    }

    goto_trace_log(
        agent_state,
        state,
        &key,
        session_id,
        final_visual_phash,
        format!("[Strategy: {}]\n{}", strategy_used, tool_call_result),
        tool_call_result,
        success,
        error_msg.clone(),
        current_tool_name.clone(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
    )?;

    if !success && !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        let failure_content = error_msg
            .clone()
            .or_else(|| history_entry.clone())
            .or_else(|| action_output.clone());
        if let Some(content) = failure_content {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                let tool_msg = ioi_types::app::agentic::ChatMessage {
                    role: "tool".to_string(),
                    content: format!("Tool Output ({}): {}", current_tool_name, trimmed),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    trace_hash: None,
                };
                let _ = service
                    .append_chat_to_scs(session_id, &tool_msg, block_height)
                    .await?;
            }
        }
    }

    // Failure counter is primarily managed in goto_trace_log.
    // We only override it for explicit escalation or lifecycle transitions.
    if enforce_system_fail_terminal_status(
        &current_tool_name,
        &mut agent_state.status,
        error_msg.as_deref(),
    ) {
        log::info!("SystemFail executed: Forcing IMMEDIATE escalation state (failures=3)");
        agent_state.consecutive_failures = 3;
    } else if !stop_condition_hit && (success || is_lifecycle_action) {
        agent_state.consecutive_failures = 0;
    }

    if !is_gated {
        if let Some(tx) = &service.event_sender {
            let output_str = action_output
                .or_else(|| if success { history_entry.clone() } else { None })
                .unwrap_or_else(|| {
                    error_msg
                        .clone()
                        .unwrap_or_else(|| "Unknown error".to_string())
                });
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: pre_state_summary.step_index,
                tool_name: current_tool_name.clone(),
                output: output_str,
                agent_status: get_status_str(&agent_state.status),
            });

            if let Some(chat_output) = terminal_chat_reply_output {
                verification_checks.push("terminal_chat_reply_emitted=true".to_string());
                if current_tool_name != "chat__reply" {
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id,
                        step_index: pre_state_summary.step_index,
                        tool_name: "chat__reply".to_string(),
                        output: chat_output,
                        agent_status: get_status_str(&agent_state.status),
                    });
                }
            }
        }
    }

    if !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        agent_state.step_count += 1;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_approval = None;
    }

    // ... [Max steps check] ...
    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running
    {
        agent_state.status = AgentStatus::Completed(None);
    }

    let mut artifacts = extract_artifacts(error_msg.as_deref(), history_entry.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));

    let post_state = build_post_state_summary(agent_state, success, verification_checks);
    let policy_binding = policy_binding_hash(&intent_hash, &policy_decision);
    let incident_fields =
        incident_receipt_fields(load_incident_state(state, &session_id)?.as_ref());
    let failure_class_name = failure_class
        .map(|class| class.as_str().to_string())
        .unwrap_or_default();

    let receipt = RoutingReceiptEvent {
        session_id,
        step_index: pre_state_summary.step_index,
        intent_hash,
        policy_decision,
        tool_name: current_tool_name,
        tool_version: tool_version.to_string(),
        pre_state: pre_state_summary,
        action_json: serde_json::to_string(&action_payload).unwrap_or_else(|_| "{}".to_string()),
        post_state,
        artifacts,
        failure_class: failure_class.map(to_routing_failure_class),
        failure_class_name,
        intent_class: incident_fields.intent_class,
        incident_id: incident_fields.incident_id,
        incident_stage: incident_fields.incident_stage,
        strategy_name: incident_fields.strategy_name,
        strategy_node: incident_fields.strategy_node,
        gate_state: incident_fields.gate_state,
        resolution_action: incident_fields.resolution_action,
        stop_condition_hit,
        escalation_path,
        scs_lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    Ok(())
    }
