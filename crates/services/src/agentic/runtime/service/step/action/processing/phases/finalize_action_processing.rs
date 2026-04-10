use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalChatReplyLayoutProfile {
    SingleSnapshot,
    DocumentBriefing,
    StoryCollection,
    Other,
}

impl TerminalChatReplyLayoutProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::SingleSnapshot => "single_snapshot",
            Self::DocumentBriefing => "document_briefing",
            Self::StoryCollection => "story_collection",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TerminalChatReplyShapeFacts {
    heading_present: bool,
    single_snapshot_heading_present: bool,
    story_header_count: usize,
    comparison_label_count: usize,
    run_date_present: bool,
    run_timestamp_present: bool,
    overall_confidence_present: bool,
}

fn observe_terminal_chat_reply_shape(summary: &str) -> TerminalChatReplyShapeFacts {
    let lines = summary
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let heading_present = lines.first().is_some_and(|line| {
        line.starts_with("Briefing for '") || line.starts_with("Web briefing (as of ")
    });
    let single_snapshot_heading_present = lines.first().is_some_and(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("right now") && lower.contains("as of ")
    });
    let story_header_count = lines
        .iter()
        .filter(|line| {
            line.strip_prefix("Story ")
                .and_then(|rest| rest.split_once(':'))
                .is_some()
        })
        .count();
    let comparison_label_count = lines
        .iter()
        .filter(|line| line.eq_ignore_ascii_case("Comparison:"))
        .count();
    let run_date_present = lines.iter().any(|line| {
        line.starts_with("Run date (UTC):") && !line["Run date (UTC):".len()..].trim().is_empty()
    });
    let run_timestamp_present = lines.iter().any(|line| {
        line.starts_with("Run timestamp (UTC):")
            && !line["Run timestamp (UTC):".len()..].trim().is_empty()
    });
    let overall_confidence_present = lines.iter().any(|line| {
        line.starts_with("Overall confidence:")
            && !line["Overall confidence:".len()..].trim().is_empty()
    });

    TerminalChatReplyShapeFacts {
        heading_present,
        single_snapshot_heading_present,
        story_header_count,
        comparison_label_count,
        run_date_present,
        run_timestamp_present,
        overall_confidence_present,
    }
}

fn terminal_chat_reply_layout_profile(
    facts: &TerminalChatReplyShapeFacts,
) -> TerminalChatReplyLayoutProfile {
    if facts.heading_present && facts.story_header_count == 0 && facts.comparison_label_count == 0 {
        return TerminalChatReplyLayoutProfile::DocumentBriefing;
    }
    if facts.story_header_count > 0 || facts.comparison_label_count > 0 {
        return TerminalChatReplyLayoutProfile::StoryCollection;
    }
    if facts.single_snapshot_heading_present {
        return TerminalChatReplyLayoutProfile::SingleSnapshot;
    }
    TerminalChatReplyLayoutProfile::Other
}

fn patch_build_verify_patch_miss_receipt_evidence(
    current_tool_name: &str,
    error_msg: Option<&str>,
    executed_tool_jcs: Option<&[u8]>,
    tool_call_result: &str,
    step_index: u32,
) -> Option<String> {
    if current_tool_name != "filesystem__patch" {
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
        "step={step_index};tool=filesystem__patch;path={path};reason=search_block_not_found"
    ))
}

fn emit_terminal_chat_reply_postcondition_receipts(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    summary: &str,
    verification_checks: &mut Vec<String>,
) {
    let reply_digest = sha256(summary.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        intent_id,
        "postcondition",
        "terminal_chat_reply_binding",
        true,
        &format!(
            "probe_source=action.chat_reply_binding.v1;observed_value={};evidence_type=sha256",
            reply_digest
        ),
        Some("action.chat_reply_binding.v1"),
        Some(reply_digest.as_str()),
        Some("sha256"),
        None,
        None,
        None,
    );
    verification_checks.push("cec_postcondition_terminal_chat_reply_binding=true".to_string());
    verification_checks.push(format!("terminal_chat_reply_sha256={}", reply_digest));

    let shape_facts = observe_terminal_chat_reply_shape(summary);
    let layout_profile = terminal_chat_reply_layout_profile(&shape_facts);
    let emit_shape_receipt =
        |key: &str, satisfied: bool, observed_value: &str, evidence_type: &str| {
            emit_execution_contract_receipt_event_with_observation(
                service,
                session_id,
                step_index,
                intent_id,
                "postcondition",
                key,
                satisfied,
                &format!(
                    "probe_source=action.chat_reply_shape.v1;observed_value={};evidence_type={}",
                    observed_value, evidence_type
                ),
                Some("action.chat_reply_shape.v1"),
                Some(observed_value),
                Some(evidence_type),
                None,
                None,
                None,
            );
        };

    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        intent_id,
        "postcondition",
        "terminal_chat_reply_layout_profile",
        true,
        &format!(
            "probe_source=action.chat_reply_shape.v1;observed_value={};evidence_type=label",
            layout_profile.as_str()
        ),
        Some("action.chat_reply_shape.v1"),
        Some(layout_profile.as_str()),
        Some("label"),
        None,
        None,
        None,
    );

    let story_header_count = shape_facts.story_header_count.to_string();
    emit_shape_receipt(
        "terminal_chat_reply_story_headers_absent",
        shape_facts.story_header_count == 0,
        story_header_count.as_str(),
        "scalar",
    );
    let comparison_label_count = shape_facts.comparison_label_count.to_string();
    emit_shape_receipt(
        "terminal_chat_reply_comparison_absent",
        shape_facts.comparison_label_count == 0,
        comparison_label_count.as_str(),
        "scalar",
    );
    let temporal_anchor_summary = format!(
        "run_date_present={};run_timestamp_present={}",
        shape_facts.run_date_present, shape_facts.run_timestamp_present
    );
    emit_shape_receipt(
        "terminal_chat_reply_temporal_anchor_floor",
        shape_facts.run_date_present && shape_facts.run_timestamp_present,
        temporal_anchor_summary.as_str(),
        "summary",
    );
    let postamble_summary = format!(
        "run_date_present={};run_timestamp_present={};overall_confidence_present={}",
        shape_facts.run_date_present,
        shape_facts.run_timestamp_present,
        shape_facts.overall_confidence_present
    );
    emit_shape_receipt(
        "terminal_chat_reply_postamble_floor",
        shape_facts.run_date_present
            && shape_facts.run_timestamp_present
            && shape_facts.overall_confidence_present,
        postamble_summary.as_str(),
        "summary",
    );
    verification_checks.push(format!(
        "terminal_chat_reply_layout_profile={}",
        layout_profile.as_str()
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_story_header_count={}",
        shape_facts.story_header_count
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_comparison_label_count={}",
        shape_facts.comparison_label_count
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_run_date_present={}",
        shape_facts.run_date_present
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_run_timestamp_present={}",
        shape_facts.run_timestamp_present
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_overall_confidence_present={}",
        shape_facts.overall_confidence_present
    ));
}

pub(crate) async fn finalize_action_processing(
    ctx: FinalizeActionProcessingContext<'_, '_>,
    state_in: ActionProcessingState,
) -> Result<(), TransactionError> {
    let FinalizeActionProcessingContext {
        service,
        state,
        agent_state,
        rules,
        session_id,
        block_height,
        strategy_used,
        tool_call_result,
        final_visual_phash,
        key,
        routing_decision,
        pre_state_summary,
        tool_version,
    } = ctx;

    let ActionProcessingState {
        policy_decision,
        action_payload,
        intent_hash,
        retry_intent_hash,
        mut success,
        mut error_msg,
        is_gated,
        mut is_lifecycle_action,
        current_tool_name,
        mut history_entry,
        mut action_output,
        trace_visual_hash,
        executed_tool_jcs,
        mut failure_class,
        mut stop_condition_hit,
        mut escalation_path,
        mut remediation_queued,
        mut verification_checks,
        awaiting_sudo_password,
        mut awaiting_clarification,
        command_probe_completed: _command_probe_completed,
        invalid_tool_call_fail_fast: _invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web: _invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox: _invalid_tool_call_fail_fast_mailbox,
        mut terminal_chat_reply_output,
    } = state_in;
    let trace_visual_hash = trace_visual_hash.unwrap_or(final_visual_phash);
    let prior_consecutive_failures = agent_state.consecutive_failures;
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
        if is_cec_terminal_error(error_msg.as_deref()) {
            stop_condition_hit = true;
            escalation_path = Some("execution_contract_terminal".to_string());
            is_lifecycle_action = true;
            remediation_queued = false;
            agent_state.execution_queue.clear();
            let terminal_reason = error_msg
                .clone()
                .unwrap_or_else(|| "ERROR_CLASS=ExecutionContractViolation".to_string());
            agent_state.status = AgentStatus::Failed(terminal_reason);
            verification_checks.push("cec_terminal_error=true".to_string());
        } else {
            failure_class = classify_failure(error_msg.as_deref(), &policy_decision);
            if let Some(class) = failure_class {
                let target_id = crate::agentic::runtime::service::step::anti_loop::specialized_attempt_target_id(
                    state,
                    service.memory_runtime.as_ref(),
                    &current_tool_name,
                    executed_tool_jcs.as_deref(),
                )
                .or_else(|| {
                    agent_state.target.as_ref().and_then(|target| {
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
                            .map(str::to_string)
                    })
                });
                let command_scope = agent_state
                    .resolved_intent
                    .as_ref()
                    .map(|resolved| {
                        resolved.scope
                            == ioi_types::app::agentic::IntentScopeProfile::CommandExecution
                    })
                    .unwrap_or(false);
                let raw_window_fingerprint = if trace_visual_hash == [0u8; 32] {
                    None
                } else {
                    Some(hex::encode(trace_visual_hash))
                };
                let window_fingerprint = crate::agentic::runtime::service::step::anti_loop::canonical_attempt_window_fingerprint(
                    class,
                    command_scope,
                    raw_window_fingerprint.as_deref(),
                );
                let retry_hash = retry_intent_hash.as_deref().unwrap_or(intent_hash.as_str());
                let attempt_key = build_attempt_key(
                    retry_hash,
                    routing_decision.tier,
                    &current_tool_name,
                    target_id.as_deref(),
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
                } else if let Some(recovery_tool) =
                    attempt_patch_build_verify_runtime_patch_miss_repair(
                        state,
                        agent_state,
                        session_id,
                        &current_tool_name,
                        error_msg.as_deref(),
                        &tool_call_result,
                        &mut verification_checks,
                    )
                {
                    if let Some(evidence) = patch_build_verify_patch_miss_receipt_evidence(
                        &current_tool_name,
                        error_msg.as_deref(),
                        executed_tool_jcs.as_deref(),
                        &tool_call_result,
                        pre_state_summary.step_index,
                    ) {
                        crate::agentic::runtime::service::step::action::support::mark_execution_receipt_with_value(
                            &mut agent_state.tool_execution_log,
                            "workspace_patch_miss_observed",
                            evidence,
                        );
                        verification_checks.push("runtime_patch_miss_observed=true".to_string());
                    }
                    let nonce = agent_state.step_count as u64
                        + agent_state.execution_queue.len() as u64
                        + 1;
                    let request = tool_to_action_request(&recovery_tool, session_id, nonce)?;
                    agent_state.execution_queue.insert(0, request);
                    stop_condition_hit = false;
                    escalation_path = None;
                    is_lifecycle_action = true;
                    remediation_queued = true;
                    success = true;
                    error_msg = None;
                    history_entry =
                        Some("Queued deterministic patch-miss recovery action.".to_string());
                    action_output = history_entry.clone();
                    agent_state.status = AgentStatus::Running;
                    agent_state.recent_actions.clear();
                    verification_checks.push("runtime_patch_miss_recovery_queued=true".to_string());
                } else {
                    if let Some(evidence) = patch_build_verify_patch_miss_receipt_evidence(
                        &current_tool_name,
                        error_msg.as_deref(),
                        executed_tool_jcs.as_deref(),
                        &tool_call_result,
                        pre_state_summary.step_index,
                    ) {
                        crate::agentic::runtime::service::step::action::support::mark_execution_receipt_with_value(
                            &mut agent_state.tool_execution_log,
                            "workspace_patch_miss_observed",
                            evidence,
                        );
                        verification_checks.push("runtime_patch_miss_observed=true".to_string());
                    }
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
                            ) = if let Some(existing) = incident_state.as_ref().filter(|i| i.active)
                            {
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
                        if maybe_enqueue_lowercase_rename_recovery(
                            agent_state,
                            session_id,
                            class,
                            &current_tool_name,
                        )? {
                            stop_condition_hit = false;
                            escalation_path = None;
                            is_lifecycle_action = true;
                            remediation_queued = true;
                            success = true;
                            error_msg = None;
                            history_entry = Some(
                                "Queued deterministic lowercase-rename recovery actions."
                                    .to_string(),
                            );
                            action_output = history_entry.clone();
                            agent_state.status = AgentStatus::Running;
                            agent_state.recent_actions.clear();
                            verification_checks.push(
                                "workspace_lowercase_rename_recovery_queued=true".to_string(),
                            );
                        } else {
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
                                agent_state.consecutive_failures =
                                    agent_state.consecutive_failures.max(3);
                            }
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
                            agent_state.consecutive_failures =
                                agent_state.consecutive_failures.max(3);
                        }
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
        trace_visual_hash,
        format!("[Strategy: {}]\n{}", strategy_used, tool_call_result),
        tool_call_result,
        success,
        error_msg.clone(),
        current_tool_name.clone(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
        service.memory_runtime.as_ref(),
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

    let max_steps_terminalization_due = !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && agent_state.status == AgentStatus::Running
        && !crate::agentic::runtime::utils::max_steps_completion_blocked_by_active_child(
            state,
            agent_state,
        )
        && agent_state.step_count.saturating_add(1) >= agent_state.max_steps;
    if !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && agent_state.status == AgentStatus::Running
        && agent_state.step_count.saturating_add(1) >= agent_state.max_steps
        && crate::agentic::runtime::utils::max_steps_completion_blocked_by_active_child(
            state,
            agent_state,
        )
    {
        verification_checks
            .push("max_steps_terminalization_deferred_for_active_child=true".to_string());
    }
    if max_steps_terminalization_due {
        if let Some(pending) = agent_state.pending_search_completion.clone() {
            if let Some(reason) = web_pipeline_completion_reason(&pending, web_pipeline_now_ms()) {
                let intent_id = resolved_intent_id(agent_state);
                let mut summary_candidates = Vec::new();
                if let Some(hybrid_summary) =
                    synthesize_web_pipeline_reply_hybrid(service, &pending, reason).await
                {
                    summary_candidates.push(
                        crate::agentic::runtime::service::step::queue::web_pipeline::FinalWebSummaryCandidate {
                            provider: "hybrid",
                            summary: hybrid_summary,
                        },
                    );
                }
                summary_candidates.push(
                    crate::agentic::runtime::service::step::queue::web_pipeline::FinalWebSummaryCandidate {
                        provider: "deterministic",
                        summary: synthesize_web_pipeline_reply(&pending, reason),
                    },
                );
                let selection =
                    crate::agentic::runtime::service::step::queue::web_pipeline::select_final_web_summary_from_candidates(
                        &pending,
                        reason,
                        summary_candidates,
                    )
                    .expect("web summary selection requires at least one candidate");
                verification_checks
                    .push(format!("web_final_summary_provider={}", selection.provider));
                verification_checks.push(format!(
                    "web_final_summary_contract_ready={}",
                    selection.contract_ready
                ));
                for evaluation in &selection.evaluations {
                    verification_checks.push(format!(
                        "web_final_summary_candidate={}::contract_ready={}::rendered_layout={}::document_layout_met={}",
                        evaluation.provider,
                        evaluation.contract_ready,
                        evaluation.facts.briefing_rendered_layout_profile,
                        evaluation.facts.briefing_document_layout_met
                    ));
                }
                let summary = selection.summary;
                let final_facts =
                    final_web_completion_facts_with_rendered_summary(&pending, reason, &summary);
                crate::agentic::runtime::service::step::queue::emit_final_web_completion_contract_receipts(
                    service,
                    session_id,
                    pre_state_summary.step_index,
                    intent_id.as_str(),
                    &final_facts,
                );
                append_final_web_completion_receipts_with_rendered_summary(
                    &pending,
                    reason,
                    &summary,
                    &mut verification_checks,
                );
                if crate::agentic::runtime::service::step::queue::web_pipeline::final_web_completion_contract_ready(&final_facts) {
                    history_entry = Some(summary.clone());
                    action_output = Some(summary.clone());
                    terminal_chat_reply_output = Some(summary.clone());
                    is_lifecycle_action = true;
                    agent_state.pending_search_completion = None;
                    agent_state.status = AgentStatus::Completed(Some(summary));
                    verification_checks.push("web_pipeline_max_steps_terminalized=true".to_string());
                    verification_checks.push("web_pipeline_active=false".to_string());
                    verification_checks.push("terminal_chat_reply_ready=true".to_string());
                } else {
                    let missing = "receipt::final_output_contract_ready=true".to_string();
                    let contract_error = execution_contract_violation_error(&missing);
                    history_entry = Some(contract_error.clone());
                    action_output = Some(contract_error.clone());
                    terminal_chat_reply_output = Some(contract_error);
                    is_lifecycle_action = true;
                    agent_state.pending_search_completion = Some(pending);
                    agent_state.status = AgentStatus::Running;
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks
                        .push(format!("execution_contract_missing_keys={}", missing));
                    verification_checks.push(
                        "web_pipeline_terminalization_blocked_on_rendered_output=true"
                            .to_string(),
                    );
                    verification_checks.push("web_pipeline_active=true".to_string());
                    verification_checks.push("terminal_chat_reply_ready=false".to_string());
                }
            }
        }
    }

    if !is_gated {
        let composed_terminal_chat = terminal_chat_reply_output
            .as_deref()
            .map(compose_terminal_chat_reply);
        if let Some(tx) = &service.event_sender {
            let mut output_str = action_output
                .or_else(|| if success { history_entry.clone() } else { None })
                .unwrap_or_else(|| {
                    error_msg
                        .clone()
                        .unwrap_or_else(|| "Unknown error".to_string())
                });
            if success
                && current_tool_name != "chat__reply"
                && composed_terminal_chat.is_some()
                && !output_str.trim().is_empty()
            {
                output_str = "Completed. Final response emitted via chat__reply.".to_string();
                verification_checks
                    .push("terminal_tool_output_suppressed_for_chat_reply=true".to_string());
            }
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: pre_state_summary.step_index,
                tool_name: current_tool_name.clone(),
                output: output_str,
                error_class: extract_error_class_token(error_msg.as_deref()).map(str::to_string),
                agent_status: get_status_str(&agent_state.status),
            });

            if let Some(composed) = composed_terminal_chat {
                verification_checks.push(format!("response_composer_applied={}", composed.applied));
                verification_checks.push(format!(
                    "response_composer_template={}",
                    composed.template_id
                ));
                verification_checks.push(format!(
                    "response_composer_validator_passed={}",
                    composed.validator_passed
                ));
                if let Some(reason) = composed.fallback_reason {
                    verification_checks
                        .push(format!("response_composer_fallback_reason={}", reason));
                }
                verification_checks.push("terminal_chat_reply_emitted=true".to_string());
                let intent_id = resolved_intent_id(agent_state);
                if current_tool_name != "chat__reply"
                    && matches!(agent_state.status, AgentStatus::Completed(_))
                {
                    emit_completion_gate_status_event(
                        service,
                        session_id,
                        pre_state_summary.step_index,
                        intent_id.as_str(),
                        true,
                        "finalize_terminal_chat_reply_gate_passed",
                    );
                    verification_checks.push("cec_completion_gate_emitted=true".to_string());
                }
                if matches!(agent_state.status, AgentStatus::Completed(_)) {
                    emit_terminal_chat_reply_postcondition_receipts(
                        service,
                        session_id,
                        pre_state_summary.step_index,
                        intent_id.as_str(),
                        composed.output.as_str(),
                        &mut verification_checks,
                    );
                }
                if current_tool_name != "chat__reply" {
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id,
                        step_index: pre_state_summary.step_index,
                        tool_name: "chat__reply".to_string(),
                        output: composed.output,
                        error_class: None,
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
        agent_state.pending_request_nonce = None;
        agent_state.pending_approval = None;
    }

    // ... [Max steps check] ...
    if crate::agentic::runtime::utils::should_terminalize_running_agent_after_max_steps(
        state,
        agent_state,
    ) {
        agent_state.status = AgentStatus::Completed(None);
    }

    match agent_state.status {
        AgentStatus::Completed(_) => {
            let _ = service
                .update_skill_reputation(state, session_id, true, block_height)
                .await;
        }
        AgentStatus::Failed(_) => {
            let _ = service
                .update_skill_reputation(state, session_id, false, block_height)
                .await;
        }
        _ => {}
    }

    let mut artifacts = extract_artifacts(error_msg.as_deref(), history_entry.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));

    let intent_id_for_contract = resolved_intent_id(agent_state);
    persist_step_contract_evidence(
        state,
        session_id,
        pre_state_summary.step_index,
        intent_id_for_contract.as_str(),
        &verification_checks,
        prior_consecutive_failures,
    )?;

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
        lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    Ok(())
}

fn maybe_enqueue_lowercase_rename_recovery(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    failure_class: FailureClass,
    root_tool_name: &str,
) -> Result<bool, TransactionError> {
    if !matches!(failure_class, FailureClass::NoEffectAfterAction)
        || root_tool_name != "filesystem__list_directory"
    {
        return Ok(false);
    }

    let Some(plan) = parse_lowercase_rename_plan(&agent_state.goal) else {
        return Ok(false);
    };
    if plan.renames.is_empty() {
        return Ok(false);
    }

    let base_dir = plan.target_dir.trim_end_matches('/').to_string();
    let mut recovery_tools: Vec<AgentTool> = Vec::new();
    let mut destination_paths: Vec<String> = Vec::new();
    for (source_name, destination_name) in &plan.renames {
        let source_path = format!("{}/{}", base_dir, source_name);
        let destination_path = format!("{}/{}", base_dir, destination_name);
        destination_paths.push(destination_path.clone());
        recovery_tools.push(AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite: false,
        });
    }

    recovery_tools.push(AgentTool::ChatReply {
        message: format!(
            "Renamed files to lowercase in {}:\n{}",
            base_dir,
            destination_paths.join("\n")
        ),
    });

    let base_nonce = agent_state.step_count as u64 + 1;
    for (offset, tool) in recovery_tools.into_iter().rev().enumerate() {
        let request = tool_to_action_request(&tool, session_id, base_nonce + offset as u64)?;
        agent_state.execution_queue.insert(0, request);
    }

    Ok(true)
}

fn tool_to_action_request(
    tool: &AgentTool,
    session_id: [u8; 32],
    nonce: u64,
) -> Result<ActionRequest, TransactionError> {
    let target = tool.target();
    let tool_name = queue_tool_name(tool);
    let tool_value =
        serde_json::to_value(tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let mut args = tool_value
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if should_embed_queue_tool_name_metadata(&target, &tool_name) {
        if let Some(obj) = args.as_object_mut() {
            obj.insert(QUEUE_TOOL_NAME_KEY.to_string(), json!(tool_name));
        }
    }
    let params =
        serde_jcs::to_vec(&args).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    Ok(ActionRequest {
        target,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce,
    })
}

#[derive(Debug)]
struct LowercaseRenamePlan {
    target_dir: String,
    renames: Vec<(String, String)>,
}

const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";

fn should_embed_queue_tool_name_metadata(target: &ActionTarget, tool_name: &str) -> bool {
    matches!(target, ActionTarget::FsRead | ActionTarget::FsWrite)
        || (matches!(target, ActionTarget::GuiClick | ActionTarget::UiClick)
            && tool_name == "gui__click_element")
        || matches!(target, ActionTarget::BrowserInteract)
        || (matches!(target, ActionTarget::SysExec)
            && matches!(tool_name, "sys__exec_session" | "sys__exec_session_reset"))
}

fn queue_tool_name(tool: &AgentTool) -> String {
    serde_json::to_value(tool)
        .ok()
        .and_then(|value| {
            value
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("{:?}", tool.target()))
}

fn parse_lowercase_rename_plan(goal: &str) -> Option<LowercaseRenamePlan> {
    let goal_lc = goal.to_ascii_lowercase();
    if !goal_lc.contains("rename files in") || !goal_lc.contains("to lowercase") {
        return None;
    }

    let target_re = regex::Regex::new("(?i)rename\\s+files\\s+in\\s+\"([^\"]+)\"")
        .expect("lowercase-rename target regex must compile");
    let target_raw = target_re
        .captures(goal)
        .and_then(|captures| captures.get(1))
        .map(|m| m.as_str().trim().to_string())?;
    let target_dir = expand_runtime_home_alias(&target_raw);

    let pair_re = regex::Regex::new("\"([^\"]+)\"\\s*->\\s*\"([^\"]+)\"")
        .expect("lowercase-rename pair regex must compile");
    let mut renames = Vec::new();
    for captures in pair_re.captures_iter(goal) {
        let source = captures
            .get(1)
            .map(|m| m.as_str().trim())
            .unwrap_or_default();
        let destination = captures
            .get(2)
            .map(|m| m.as_str().trim())
            .unwrap_or_default();
        if source.is_empty()
            || destination.is_empty()
            || source.contains('/')
            || destination.contains('/')
        {
            continue;
        }
        renames.push((source.to_string(), destination.to_string()));
    }

    if renames.is_empty() {
        return None;
    }

    Some(LowercaseRenamePlan {
        target_dir,
        renames,
    })
}

fn expand_runtime_home_alias(path: &str) -> String {
    let trimmed = path.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            let home = home.trim_end_matches('/');
            return format!("{home}/{}", rest.trim_start_matches('/'));
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        observe_terminal_chat_reply_shape, terminal_chat_reply_layout_profile,
        TerminalChatReplyLayoutProfile,
    };

    #[test]
    fn terminal_chat_reply_shape_detects_story_collection_output() {
        let facts = observe_terminal_chat_reply_shape(
            "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\n- Example\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high",
        );

        assert!(!facts.heading_present);
        assert_eq!(facts.story_header_count, 1);
        assert_eq!(facts.comparison_label_count, 1);
        assert_eq!(
            terminal_chat_reply_layout_profile(&facts),
            TerminalChatReplyLayoutProfile::StoryCollection
        );
    }

    #[test]
    fn terminal_chat_reply_shape_detects_document_briefing_output() {
        let facts = observe_terminal_chat_reply_shape(
            "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T12:19:24Z UTC)\n\nWhat happened: NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence:\n- NIST finalized the first three standards.\n\nCitations:\n- Post-quantum cryptography | NIST | https://www.nist.gov/pqc | 2026-03-10T12:19:24Z | retrieved_utc\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high",
        );

        assert!(facts.heading_present);
        assert_eq!(facts.story_header_count, 0);
        assert_eq!(facts.comparison_label_count, 0);
        assert!(facts.run_date_present);
        assert!(facts.run_timestamp_present);
        assert!(facts.overall_confidence_present);
        assert_eq!(
            terminal_chat_reply_layout_profile(&facts),
            TerminalChatReplyLayoutProfile::DocumentBriefing
        );
    }

    #[test]
    fn terminal_chat_reply_shape_detects_single_snapshot_output() {
        let facts = observe_terminal_chat_reply_shape(
            "Right now (as of 2026-03-11T13:42:57Z UTC):\n\nCurrent conditions from cited source text: Bitcoin price right now: $86,743.63 USD.\n\nCitations:\n- Bitcoin price | index, chart and news | WorldCoinIndex | https://www.worldcoinindex.com/coin/bitcoin | 2026-03-11T13:42:57Z | retrieved_utc\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:42:57Z\nOverall confidence: high",
        );

        assert!(!facts.heading_present);
        assert!(facts.single_snapshot_heading_present);
        assert_eq!(facts.story_header_count, 0);
        assert_eq!(facts.comparison_label_count, 0);
        assert!(facts.run_date_present);
        assert!(facts.run_timestamp_present);
        assert!(facts.overall_confidence_present);
        assert_eq!(
            terminal_chat_reply_layout_profile(&facts),
            TerminalChatReplyLayoutProfile::SingleSnapshot
        );
    }
}
