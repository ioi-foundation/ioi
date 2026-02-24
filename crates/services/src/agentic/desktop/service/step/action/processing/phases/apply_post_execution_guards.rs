    {
    let is_install_package_tool = current_tool_name == "sys__install_package"
        || current_tool_name == "sys::install_package"
        || current_tool_name.ends_with("install_package");
    let clarification_required = !success
        && error_msg
            .as_deref()
            .map(|msg| requires_wait_for_clarification(&current_tool_name, msg))
            .unwrap_or(false);

    if !success
        && is_install_package_tool
        && error_msg
            .as_deref()
            .map(is_sudo_password_required_install_error)
            .unwrap_or(false)
    {
        awaiting_sudo_password = true;
        stop_condition_hit = true;
        escalation_path = Some("wait_for_sudo_password".to_string());
        is_lifecycle_action = true;
        failure_class = Some(FailureClass::PermissionOrApprovalRequired);
        agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_sudo_password",
            FailureClass::PermissionOrApprovalRequired,
            error_msg.as_deref(),
        )?;
        // Discard any queued remediation actions so resume prioritizes retrying
        // the canonical pending install with user-provided runtime secret.
        agent_state.execution_queue.clear();
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = Some(tool_call_result.clone());
        agent_state.pending_visual_hash = Some(final_visual_phash);
        agent_state.last_screen_phash = Some(final_visual_phash);
        if let Some(tool_jcs) = executed_tool_jcs.clone() {
            let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
                TransactionError::Invalid(format!("Failed to hash pending install tool: {}", e))
            })?;
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(tool_hash_bytes.as_ref());
            agent_state.pending_tool_jcs = Some(tool_jcs);
            agent_state.pending_tool_hash = Some(hash_arr);
        }
        if let Some(err_text) = error_msg.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", current_tool_name, err_text),
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
        let sys_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content: "System: WAIT_FOR_SUDO_PASSWORD. Install requires sudo password. Enter password to retry once."
                .to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        let _ = service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_sudo_password=true".to_string());
    }

    if clarification_required {
        awaiting_clarification = true;
        stop_condition_hit = true;
        escalation_path = Some("wait_for_clarification".to_string());
        is_lifecycle_action = true;
        failure_class = Some(FailureClass::UserInterventionNeeded);
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_clarification",
            FailureClass::UserInterventionNeeded,
            error_msg.as_deref(),
        )?;
        agent_state.status =
            AgentStatus::Paused("Waiting for clarification on target identity.".to_string());
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_visual_hash = None;
        agent_state.execution_queue.clear();

        if let Some(err_text) = error_msg.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", current_tool_name, err_text),
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
        let sys_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content:
                "System: WAIT_FOR_CLARIFICATION. Target identity could not be resolved. Provide clarification input to continue."
                    .to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        let _ = service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_clarification=true".to_string());
    }

    if invalid_tool_call_fail_fast
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        let summary = if invalid_tool_call_fail_fast_mailbox {
            format!(
                "Mailbox connector action executed, but response synthesis failed due schema validation. Please retry the request. Run timestamp (UTC ms): {}.",
                block_timestamp_ns / 1_000_000
            )
        } else {
            "Invalid tool call generated during web research. Stopping early to avoid recovery churn."
                .to_string()
        };
        success = true;
        error_msg = None;
        stop_condition_hit = true;
        escalation_path = Some("invalid_tool_call_fail_fast".to_string());
        is_lifecycle_action = true;
        action_output = Some(summary.clone());
        if invalid_tool_call_fail_fast_mailbox {
            terminal_chat_reply_output = Some(summary.clone());
            verification_checks.push("mailbox_invalid_tool_call_fail_fast=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=true".to_string());
        }
        agent_state.status = AgentStatus::Completed(Some(summary));
        agent_state.execution_queue.clear();
        agent_state.pending_search_completion = None;
        verification_checks.push("invalid_tool_call_fail_fast=true".to_string());
    }

    if invalid_tool_call_bootstrap_web
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        let goal = agent_state.goal.clone();
        let queued = queue_web_search_bootstrap(agent_state, session_id, &goal)?;
        success = true;
        error_msg = None;
        stop_condition_hit = false;
        escalation_path = None;
        is_lifecycle_action = true;
        let note = if queued {
            "Model returned empty tool output; bootstrapped deterministic web__search.".to_string()
        } else {
            "Model returned empty tool output; web__search bootstrap already queued.".to_string()
        };
        history_entry = Some(note.clone());
        action_output = Some(note);
        agent_state.status = AgentStatus::Running;
        verification_checks.push("invalid_tool_call_bootstrap_web=true".to_string());
    }

    if !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && current_tool_name == "web__read"
    {
        if let Some(mut pending) = agent_state.pending_search_completion.clone() {
            let read_url = extract_web_read_url_from_payload(&action_payload).unwrap_or_default();
            if !read_url.is_empty() {
                mark_pending_web_attempted(&mut pending, &read_url);
            }

            if success {
                if let Some(bundle) = history_entry.as_deref().and_then(parse_web_evidence_bundle) {
                    append_pending_web_success_from_bundle(&mut pending, &bundle, &read_url);
                } else {
                    append_pending_web_success_fallback(
                        &mut pending,
                        &read_url,
                        history_entry.as_deref(),
                    );
                }
            } else if !read_url.is_empty()
                && is_human_challenge_error(error_msg.as_deref().unwrap_or(""))
            {
                mark_pending_web_blocked(&mut pending, &read_url);
            }

            let now_ms = web_pipeline_now_ms();
            let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
            let remaining_budget_ms = web_pipeline_remaining_budget_ms(pending.deadline_ms, now_ms);
            let read_budget_required_ms = web_pipeline_required_read_budget_ms(&pending, now_ms);
            let probe_budget_required_ms = web_pipeline_required_probe_budget_ms(&pending, now_ms);
            let read_budget_allows =
                web_pipeline_can_queue_initial_read_latency_aware(&pending, now_ms);
            let probe_budget_allows =
                web_pipeline_can_queue_probe_search_latency_aware(&pending, now_ms);
            let latency_pressure = web_pipeline_latency_pressure_label(&pending, now_ms);
            let mut completion_reason = web_pipeline_completion_reason(&pending, now_ms);
            let mut queued_next = false;
            let mut queued_probe = false;
            if completion_reason.is_none() {
                let remaining_candidates = remaining_pending_web_candidates(&pending);
                let min_sources_required = pending.min_sources.max(1) as usize;
                let source_floor_unmet = pending.successful_reads.len() < min_sources_required;
                let metric_probe_followup =
                    web_pipeline_requires_metric_probe_followup(&pending, now_ms);
                let queue_probe = |pending: &mut PendingSearchCompletion,
                                   agent_state: &mut AgentState|
                 -> Result<bool, TransactionError> {
                    let mut probe_hints = pending.successful_reads.clone();
                    for hint in &pending.candidate_source_hints {
                        let hint_url = hint.url.trim();
                        if hint_url.is_empty() {
                            continue;
                        }
                        if probe_hints
                            .iter()
                            .any(|existing| existing.url.trim().eq_ignore_ascii_case(hint_url))
                        {
                            continue;
                        }
                        probe_hints.push(hint.clone());
                    }
                    if let Some(probe_query) = constraint_grounded_probe_query_with_hints(
                        &pending.query_contract,
                        pending.min_sources,
                        &probe_hints,
                        &pending.query,
                    ) {
                        let queued = queue_web_search_from_pipeline(
                            agent_state,
                            session_id,
                            &probe_query,
                            constraint_grounded_search_limit(
                                &pending.query_contract,
                                pending.min_sources,
                            ),
                        )?;
                        if queued {
                            pending.query = probe_query;
                        }
                        return Ok(queued);
                    }
                    Ok(false)
                };
                if metric_probe_followup && probe_budget_allows {
                    queued_probe = queue_probe(&mut pending, agent_state)?;
                }
                if !queued_probe && read_budget_allows {
                    if let Some(next_url) = next_pending_web_candidate(&pending) {
                        queued_next =
                            queue_web_read_from_pipeline(agent_state, session_id, &next_url)?;
                    }
                }
                if !queued_next
                    && !queued_probe
                    && source_floor_unmet
                    && remaining_candidates == 0
                    && probe_budget_allows
                {
                    queued_probe = queue_probe(&mut pending, agent_state)?;
                }
                verification_checks.push(format!(
                    "web_metric_probe_followup={}",
                    metric_probe_followup
                ));
                if !queued_next && !queued_probe && !read_budget_allows && remaining_candidates > 0
                {
                    completion_reason = Some(WebPipelineCompletionReason::DeadlineReached);
                }
                if !queued_next && !queued_probe && remaining_candidates == 0 {
                    completion_reason = Some(WebPipelineCompletionReason::ExhaustedCandidates);
                }
            }

            verification_checks.push(format!(
                "web_sources_success={}",
                pending.successful_reads.len()
            ));
            verification_checks.push(format!(
                "web_sources_blocked={}",
                pending.blocked_urls.len()
            ));
            verification_checks.push(format!("web_budget_ms={}", elapsed_ms));
            verification_checks.push(format!("web_remaining_budget_ms={}", remaining_budget_ms));
            verification_checks.push(format!(
                "web_read_budget_required_ms={}",
                read_budget_required_ms
            ));
            verification_checks.push(format!(
                "web_probe_budget_required_ms={}",
                probe_budget_required_ms
            ));
            verification_checks.push(format!("web_read_budget_allows={}", read_budget_allows));
            verification_checks.push(format!("web_probe_budget_allows={}", probe_budget_allows));
            verification_checks.push(format!(
                "web_constraint_search_probe_queued={}",
                queued_probe
            ));
            verification_checks.push(format!("web_latency_pressure={}", latency_pressure));

            if let Some(reason) = completion_reason {
                let summary = if let Some(hybrid_summary) = synthesize_web_pipeline_reply_hybrid(
                    service.reasoning_inference.clone(),
                    &pending,
                    reason,
                )
                .await
                {
                    hybrid_summary
                } else {
                    synthesize_web_pipeline_reply(&pending, reason)
                };
                success = true;
                error_msg = None;
                action_output = Some(summary.clone());
                history_entry = Some(summary.clone());
                terminal_chat_reply_output = Some(summary.clone());
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Completed(Some(summary));
                agent_state.pending_search_completion = None;
                agent_state.execution_queue.clear();
                agent_state.recent_actions.clear();
                verification_checks.push("web_pipeline_active=false".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            } else {
                let challenge = is_human_challenge_error(error_msg.as_deref().unwrap_or(""));
                agent_state.pending_search_completion = Some(pending);
                verification_checks.push("web_pipeline_active=true".to_string());
                if !success {
                    let note = if challenge {
                        format!(
                            "Skipped challenged source and continuing with alternates: {}",
                            read_url
                        )
                    } else {
                        format!(
                            "Source read failed; continuing with alternate sources: {}",
                            read_url
                        )
                    };
                    success = true;
                    error_msg = None;
                    history_entry = Some(note.clone());
                    action_output = Some(note);
                    stop_condition_hit = false;
                    escalation_path = None;
                    agent_state.status = AgentStatus::Running;
                }
            }
        }
    }
    }
