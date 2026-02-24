                {
                let action_fingerprint = retry_intent_hash.clone().unwrap_or_default();
                let command_scope = agent_state
                    .resolved_intent
                    .as_ref()
                    .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
                    .unwrap_or(false);
                if let Some(route_label) = capability_route_label(&current_tool_name) {
                    verification_checks.push(format!("capability_route_selected={}", route_label));
                    if command_scope {
                        mark_execution_receipt(
                            &mut agent_state.tool_execution_log,
                            "provider_selection",
                        );
                        verification_checks.push(receipt_marker("provider_selection"));
                    }
                }
                if command_scope
                    && matches!(
                        tool,
                        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                    )
                {
                    if agent_state.command_history.is_empty() {
                        verification_checks
                            .push("capability_execution_phase=discovery".to_string());
                        mark_execution_receipt(
                            &mut agent_state.tool_execution_log,
                            "host_discovery",
                        );
                        verification_checks.push(receipt_marker("host_discovery"));
                    }
                    verification_checks.push("capability_execution_phase=execution".to_string());
                }
                let duplicate_command_execution = command_scope
                    && matches!(
                        tool,
                        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                    )
                    && !action_fingerprint.is_empty()
                    && is_action_fingerprint_executed(
                        &agent_state.tool_execution_log,
                        &action_fingerprint,
                    );
                if duplicate_command_execution {
                    if let Some(summary) = duplicate_command_completion_summary(
                        &tool,
                        agent_state.command_history.back(),
                    ) {
                        let missing_contract_markers =
                            missing_execution_contract_markers(agent_state);
                        if missing_contract_markers.is_empty() {
                            success = true;
                            error_msg = None;
                            history_entry = Some(summary.clone());
                            action_output = Some(summary.clone());
                            terminal_chat_reply_output = Some(summary.clone());
                            is_lifecycle_action = true;
                            agent_state.status = AgentStatus::Completed(Some(summary));
                            agent_state.execution_queue.clear();
                            agent_state.pending_search_completion = None;
                            verification_checks
                                .push("duplicate_action_fingerprint_terminalized=true".to_string());
                            verification_checks.push("terminal_chat_reply_ready=true".to_string());
                        } else {
                            let missing = missing_contract_markers.join(",");
                            let contract_error = execution_contract_violation_error(&missing);
                            success = false;
                            error_msg = Some(contract_error.clone());
                            history_entry = Some(contract_error.clone());
                            action_output = Some(contract_error);
                            agent_state.status = AgentStatus::Running;
                            verification_checks
                                .push("execution_contract_gate_blocked=true".to_string());
                            verification_checks
                                .push(format!("execution_contract_missing_keys={}", missing));
                            verification_checks
                                .push("duplicate_action_fingerprint_blocked=true".to_string());
                        }
                    } else {
                        let summary = duplicate_command_execution_summary(&tool);
                        success = false;
                        let duplicate_error =
                            format!("ERROR_CLASS=NoEffectAfterAction {}", summary);
                        error_msg = Some(duplicate_error.clone());
                        history_entry = Some(summary);
                        action_output = Some(duplicate_error);
                        agent_state.status = AgentStatus::Running;
                        verification_checks
                            .push("duplicate_action_fingerprint_blocked=true".to_string());
                    }
                    verification_checks.push(format!(
                        "duplicate_action_fingerprint={}",
                        action_fingerprint
                    ));
                    verification_checks.push(format!(
                        "duplicate_action_fingerprint_non_terminal={}",
                        !success
                    ));
                } else {
                    let tool_allowed = is_tool_allowed_for_resolution(
                        agent_state.resolved_intent.as_ref(),
                        &current_tool_name,
                    );

                    if !tool_allowed {
                        policy_decision = "denied".to_string();
                        success = false;
                        error_msg = Some(format!(
                    "ERROR_CLASS=PermissionOrApprovalRequired Tool '{}' blocked by global intent scope.",
                    current_tool_name
                ));
                        if !req_hash_hex.is_empty() {
                            agent_state.tool_execution_log.insert(
                                req_hash_hex.clone(),
                                ToolCallStatus::Failed("intent_scope_block".to_string()),
                            );
                        }
                    } else {
                        let timer_notification_required = command_scope
                            && requires_timer_notification_contract(agent_state)
                            && matches!(
                                tool,
                                AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                            );
                        let timer_delay_backend_armed = sys_exec_arms_timer_delay_backend(&tool);
                        let notification_path_armed = sys_exec_command_preview(&tool)
                            .as_deref()
                            .map(command_arms_deferred_notification_path)
                            .unwrap_or(false);
                        if timer_notification_required {
                            verification_checks
                                .push("timer_delay_backend_required=true".to_string());
                            verification_checks.push(format!(
                                "timer_delay_backend_detected={}",
                                timer_delay_backend_armed
                            ));
                            verification_checks
                                .push("timer_notification_path_required=true".to_string());
                            verification_checks.push(format!(
                                "timer_notification_path_detected={}",
                                notification_path_armed
                            ));
                        }

                        if timer_notification_required && !timer_delay_backend_armed {
                            verification_checks.push(format!(
                                "execution_contract_missing_keys={}",
                                postcondition_marker(TIMER_SLEEP_BACKEND_POSTCONDITION)
                            ));
                        }
                        if timer_notification_required && !notification_path_armed {
                            verification_checks.push(format!(
                                "execution_contract_missing_keys={}",
                                postcondition_marker(TIMER_NOTIFICATION_PATH_POSTCONDITION)
                            ));
                        }

                        let target_hash_opt = agent_state
                            .pending_approval
                            .as_ref()
                            .and_then(|t| t.visual_hash)
                            .or(agent_state.last_screen_phash);
                        if let Some(target_hash) = target_hash_opt {
                            let _ = service.restore_visual_context(target_hash).await;
                        }

                        // [FIX] Pass the required InferenceRuntime (reasoning) to ToolExecutor constructor inside handle_action_execution
                        match service
                            .handle_action_execution_with_state(
                                state,
                                call_context,
                                tool.clone(),
                                session_id,
                                agent_state.step_count,
                                final_visual_phash,
                                &rules,
                                &agent_state,
                                &os_driver,
                                None,
                            )
                            .await
                        {
                            Ok((s, entry, e)) => {
                                success = s;
                                error_msg = e;
                                history_entry = entry.clone();

                                // Orchestration meta-tools require access to chain state; execute them
                                // on the primary path here instead of the stateless ToolExecutor.
                                if success {
                                    match &tool {
                                        AgentTool::AgentDelegate { goal, budget } => {
                                            let tool_jcs = match serde_jcs::to_vec(&tool) {
                                                Ok(bytes) => bytes,
                                                Err(err) => {
                                                    success = false;
                                                    error_msg = Some(format!(
                                                "ERROR_CLASS=UnexpectedState Failed to encode delegation tool: {}",
                                                err
                                            ));
                                                    history_entry = None;
                                                    Vec::new()
                                                }
                                            };

                                            if success {
                                                match sha256(&tool_jcs) {
                                                    Ok(tool_hash) => {
                                                        match spawn_delegated_child_session(
                                                            service,
                                                            state,
                                                            agent_state,
                                                            tool_hash,
                                                            goal,
                                                            *budget,
                                                            pre_state_summary.step_index,
                                                            block_height,
                                                        )
                                                        .await
                                                        {
                                                            Ok(child_session_id) => {
                                                                history_entry = Some(format!(
                                                        "{{\"child_session_id_hex\":\"{}\"}}",
                                                        hex::encode(child_session_id)
                                                    ));
                                                                error_msg = None;
                                                            }
                                                            Err(err) => {
                                                                success = false;
                                                                error_msg = Some(err.to_string());
                                                                history_entry = None;
                                                            }
                                                        }
                                                    }
                                                    Err(err) => {
                                                        success = false;
                                                        error_msg = Some(format!(
                                                    "ERROR_CLASS=UnexpectedState Delegation hash failed: {}",
                                                    err
                                                ));
                                                        history_entry = None;
                                                    }
                                                }
                                            }
                                        }
                                        AgentTool::AgentAwait {
                                            child_session_id_hex,
                                        } => {
                                            match child_session::await_child_session_status(
                                                state,
                                                child_session_id_hex,
                                            ) {
                                                Ok(out) => {
                                                    history_entry = Some(out);
                                                    error_msg = None;
                                                }
                                                Err(err) => {
                                                    success = false;
                                                    error_msg = Some(err);
                                                    history_entry = None;
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }

                                if matches!(
                                    &tool,
                                    AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                                ) {
                                    if let Some(raw_entry) =
                                        command_history::extract_command_history(&history_entry)
                                    {
                                        verification_checks.push(
                                            "capability_execution_evidence=command_history"
                                                .to_string(),
                                        );
                                        verification_checks.push(format!(
                                            "capability_execution_last_exit_code={}",
                                            raw_entry.exit_code
                                        ));
                                        if command_scope {
                                            mark_execution_postcondition(
                                                &mut agent_state.tool_execution_log,
                                                "execution_artifact",
                                            );
                                            verification_checks
                                                .push(postcondition_marker("execution_artifact"));
                                        }
                                        let history_entry =
                                            command_history::scrub_command_history_fields(
                                                &service.scrubber,
                                                raw_entry,
                                            )
                                            .await;
                                        command_history::append_to_bounded_history(
                                            &mut agent_state.command_history,
                                            history_entry,
                                            MAX_COMMAND_HISTORY,
                                        );
                                    }
                                }

                                if (success || command_probe_completed) && !req_hash_hex.is_empty()
                                {
                                    agent_state.tool_execution_log.insert(
                                        req_hash_hex.clone(),
                                        ToolCallStatus::Executed("success".into()),
                                    );
                                    if let Some(retry_hash) = retry_intent_hash.as_deref() {
                                        mark_action_fingerprint_executed(
                                            &mut agent_state.tool_execution_log,
                                            retry_hash,
                                            "success",
                                        );
                                    }
                                    agent_state.pending_approval = None;
                                    agent_state.pending_tool_jcs = None;
                                }

                                if success {
                                    if matches!(
                                        &tool,
                                        AgentTool::SysExec { .. }
                                            | AgentTool::SysExecSession { .. }
                                    ) {
                                        if command_scope
                                            && requires_timer_notification_contract(agent_state)
                                        {
                                            if sys_exec_arms_timer_delay_backend(&tool) {
                                                mark_execution_postcondition(
                                                    &mut agent_state.tool_execution_log,
                                                    TIMER_SLEEP_BACKEND_POSTCONDITION,
                                                );
                                                verification_checks.push(postcondition_marker(
                                                    TIMER_SLEEP_BACKEND_POSTCONDITION,
                                                ));
                                            }
                                            if let Some(command_preview) =
                                                sys_exec_command_preview(&tool)
                                            {
                                                if command_arms_deferred_notification_path(
                                                    &command_preview,
                                                ) {
                                                    mark_execution_postcondition(
                                                        &mut agent_state.tool_execution_log,
                                                        TIMER_NOTIFICATION_PATH_POSTCONDITION,
                                                    );
                                                    verification_checks.push(postcondition_marker(
                                                        TIMER_NOTIFICATION_PATH_POSTCONDITION,
                                                    ));
                                                    mark_execution_receipt(
                                                        &mut agent_state.tool_execution_log,
                                                        "notification_strategy",
                                                    );
                                                    verification_checks.push(receipt_marker(
                                                        "notification_strategy",
                                                    ));
                                                    verification_checks.push(
                                                        "timer_notification_path_armed=true"
                                                            .to_string(),
                                                    );
                                                }
                                            }
                                        }
                                        if command_scope {
                                            mark_execution_receipt(
                                                &mut agent_state.tool_execution_log,
                                                "execution",
                                            );
                                            verification_checks.push(receipt_marker("execution"));
                                        }
                                        verification_checks.push(
                                            "capability_execution_phase=verification".to_string(),
                                        );
                                        if command_scope {
                                            mark_execution_receipt(
                                                &mut agent_state.tool_execution_log,
                                                "verification",
                                            );
                                            verification_checks
                                                .push(receipt_marker("verification"));
                                        }
                                    }
                                    if let Some(entry) = history_entry.clone() {
                                        let tool_msg = ioi_types::app::agentic::ChatMessage {
                                            role: "tool".to_string(),
                                            content: entry,
                                            timestamp: SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .unwrap()
                                                .as_millis()
                                                as u64,
                                            trace_hash: None,
                                        };
                                        let _ = service
                                            .append_chat_to_scs(session_id, &tool_msg, block_height)
                                            .await?;
                                    }
                                }

                                match &tool {
                                    AgentTool::AgentComplete { result } => {
                                        let missing_contract_markers =
                                            missing_execution_contract_markers(agent_state);
                                        if !missing_contract_markers.is_empty() {
                                            let missing = missing_contract_markers.join(",");
                                            let contract_error =
                                                execution_contract_violation_error(&missing);
                                            success = false;
                                            error_msg = Some(contract_error.clone());
                                            history_entry = Some(contract_error.clone());
                                            action_output = Some(contract_error);
                                            agent_state.status = AgentStatus::Running;
                                            verification_checks.push(
                                                "execution_contract_gate_blocked=true".to_string(),
                                            );
                                            verification_checks.push(format!(
                                                "execution_contract_missing_keys={}",
                                                missing
                                            ));
                                        } else {
                                            let completed_result = if is_system_clock_read_intent(
                                                agent_state.resolved_intent.as_ref(),
                                            ) {
                                                summarize_system_clock_output(result)
                                                    .unwrap_or_else(|| result.clone())
                                            } else {
                                                result.clone()
                                            };
                                            let completed_result = enrich_command_scope_summary(
                                                &completed_result,
                                                agent_state,
                                            );
                                            agent_state.status = AgentStatus::Completed(Some(
                                                completed_result.clone(),
                                            ));
                                            is_lifecycle_action = true;
                                            action_output = Some(completed_result.clone());
                                            if !completed_result.trim().is_empty() {
                                                terminal_chat_reply_output =
                                                    Some(completed_result.clone());
                                                verification_checks.push(
                                                    "terminal_chat_reply_ready=true".to_string(),
                                                );
                                            }
                                            evaluate_and_crystallize(
                                                service,
                                                agent_state,
                                                session_id,
                                                &completed_result,
                                            )
                                            .await;
                                        }
                                    }
                                    AgentTool::SysChangeDir { .. } => {
                                        if success {
                                            if let Some(new_cwd) = history_entry.as_ref() {
                                                agent_state.working_directory = new_cwd.clone();
                                            }
                                        }
                                    }
                                    AgentTool::ChatReply { message } => {
                                        let missing_contract_markers =
                                            missing_execution_contract_markers(agent_state);
                                        if !missing_contract_markers.is_empty() {
                                            let missing = missing_contract_markers.join(",");
                                            let contract_error =
                                                execution_contract_violation_error(&missing);
                                            success = false;
                                            error_msg = Some(contract_error.clone());
                                            history_entry = Some(contract_error.clone());
                                            action_output = Some(contract_error);
                                            agent_state.status = AgentStatus::Running;
                                            verification_checks.push(
                                                "execution_contract_gate_blocked=true".to_string(),
                                            );
                                            verification_checks.push(format!(
                                                "execution_contract_missing_keys={}",
                                                missing
                                            ));
                                        } else {
                                            let message =
                                                enrich_command_scope_summary(message, agent_state);
                                            agent_state.status =
                                                AgentStatus::Completed(Some(message.clone()));
                                            is_lifecycle_action = true;
                                            action_output = Some(message.clone());
                                            terminal_chat_reply_output = Some(message.clone());
                                            evaluate_and_crystallize(
                                                service,
                                                agent_state,
                                                session_id,
                                                &message,
                                            )
                                            .await;
                                        }
                                    }
                                    AgentTool::OsLaunchApp { app_name } => {
                                        if success
                                            && should_auto_complete_open_app_goal(
                                                &agent_state.goal,
                                                app_name,
                                                agent_state
                                                    .target
                                                    .as_ref()
                                                    .and_then(|target| target.app_hint.as_deref()),
                                            )
                                        {
                                            let summary = format!("Opened {}.", app_name);
                                            agent_state.status =
                                                AgentStatus::Completed(Some(summary.clone()));
                                            is_lifecycle_action = true;
                                            action_output = Some(summary.clone());
                                            terminal_chat_reply_output = Some(summary);
                                            verification_checks
                                                .push("terminal_chat_reply_ready=true".to_string());
                                            agent_state.execution_queue.clear();
                                            agent_state.pending_search_completion = None;
                                            log::info!(
                                    "Auto-completed app-launch session {} after successful os__launch_app.",
                                    hex::encode(&session_id[..4])
                                );
                                        }
                                    }
                                    AgentTool::SysExec { .. }
                                    | AgentTool::SysExecSession { .. } => {
                                        if is_command_probe_intent(
                                            agent_state.resolved_intent.as_ref(),
                                        ) {
                                            if let Some(raw) = history_entry.as_deref() {
                                                if let Some(summary) =
                                                    summarize_command_probe_output(&tool, raw)
                                                {
                                                    // Probe markers are deterministic completion signals even
                                                    // when the underlying command exits non-zero.
                                                    command_probe_completed = true;
                                                    success = true;
                                                    error_msg = None;
                                                    agent_state.status = AgentStatus::Completed(
                                                        Some(summary.clone()),
                                                    );
                                                    is_lifecycle_action = true;
                                                    action_output = Some(summary);
                                                    agent_state.execution_queue.clear();
                                                    agent_state.pending_search_completion = None;
                                                }
                                            }
                                        } else if is_system_clock_read_intent(
                                            agent_state.resolved_intent.as_ref(),
                                        ) {
                                            let summary = history_entry
                                                .as_deref()
                                                .and_then(summarize_system_clock_output)
                                                .unwrap_or_else(|| {
                                                    "Current UTC time: <unavailable>".to_string()
                                                });
                                            success = true;
                                            error_msg = None;
                                            agent_state.status =
                                                AgentStatus::Completed(Some(summary.clone()));
                                            is_lifecycle_action = true;
                                            action_output = Some(summary.clone());
                                            terminal_chat_reply_output = Some(summary);
                                            agent_state.execution_queue.clear();
                                            agent_state.pending_search_completion = None;
                                        }
                                    }
                                    AgentTool::MemorySearch { query } => {
                                        let mut promoted_memory_search = false;
                                        if success && should_use_web_research_path(agent_state) {
                                            if let Some(raw) = history_entry.as_deref() {
                                                if let Some(bundle) = parse_web_evidence_bundle(raw)
                                                {
                                                    if bundle.tool == "web__search" {
                                                        promoted_memory_search = true;
                                                        current_tool_name =
                                                            "web__search".to_string();
                                                        verification_checks.push(
                                                        "memory_search_promoted_to_web_search=true"
                                                            .to_string(),
                                                    );
                                                        apply_pre_read_bundle(
                                                            service,
                                                            agent_state,
                                                            session_id,
                                                            pre_state_summary.step_index,
                                                            &bundle,
                                                            query,
                                                            &mut verification_checks,
                                                            &mut history_entry,
                                                            &mut action_output,
                                                            &mut terminal_chat_reply_output,
                                                            &mut is_lifecycle_action,
                                                        )
                                                        .await?;
                                                    }
                                                }
                                            }
                                        }

                                        if !promoted_memory_search
                                            && success
                                            && should_use_web_research_path(agent_state)
                                            && agent_state.pending_search_completion.is_none()
                                            && history_entry
                                                .as_deref()
                                                .map(is_empty_memory_search_output)
                                                .unwrap_or(true)
                                        {
                                            let bootstrap_query = if query.trim().is_empty() {
                                                agent_state.goal.clone()
                                            } else {
                                                query.clone()
                                            };
                                            let queued = queue_web_search_bootstrap(
                                                agent_state,
                                                session_id,
                                                &bootstrap_query,
                                            )?;
                                            verification_checks.push(
                                                "web_search_bootstrap_from_memory=true".to_string(),
                                            );
                                            let note = if queued {
                                                "No memory hits for this news query; queued deterministic web__search.".to_string()
                                            } else {
                                                "No memory hits for this news query; deterministic web__search was already queued."
                                            .to_string()
                                            };
                                            history_entry = Some(note.clone());
                                            action_output = Some(note);
                                            agent_state.status = AgentStatus::Running;
                                        }
                                    }
                                    AgentTool::WebSearch { query, .. } => {
                                        if success && should_use_web_research_path(agent_state) {
                                            if let Some(raw) = history_entry.as_deref() {
                                                if let Some(bundle) = parse_web_evidence_bundle(raw)
                                                {
                                                    apply_pre_read_bundle(
                                                        service,
                                                        agent_state,
                                                        session_id,
                                                        pre_state_summary.step_index,
                                                        &bundle,
                                                        query,
                                                        &mut verification_checks,
                                                        &mut history_entry,
                                                        &mut action_output,
                                                        &mut terminal_chat_reply_output,
                                                        &mut is_lifecycle_action,
                                                    )
                                                    .await?;
                                                }
                                            }
                                        }
                                    }
                                    AgentTool::SystemFail { reason, .. } => {
                                        let mailbox_intent =
                                            is_mailbox_connector_goal(&agent_state.goal);
                                        let mailbox_reason = reason.to_ascii_lowercase();
                                        if mailbox_intent
                                            && (mailbox_reason.contains("mailbox")
                                                || mailbox_reason.contains("email")
                                                || mailbox_reason.contains("mail "))
                                        {
                                            let run_timestamp_ms = block_timestamp_ns / 1_000_000;
                                            let summary = render_mailbox_access_limited_reply(
                                                &agent_state.goal,
                                                run_timestamp_ms,
                                            );
                                            success = true;
                                            error_msg = None;
                                            history_entry = Some(summary.clone());
                                            action_output = Some(summary.clone());
                                            terminal_chat_reply_output = Some(summary.clone());
                                            current_tool_name = "chat__reply".to_string();
                                            is_lifecycle_action = true;
                                            agent_state.status =
                                                AgentStatus::Completed(Some(summary));
                                            agent_state.pending_search_completion = None;
                                            agent_state.execution_queue.clear();
                                            agent_state.recent_actions.clear();
                                            verification_checks.push(
                                                "mailbox_system_fail_degraded_to_reply=true"
                                                    .to_string(),
                                            );
                                            verification_checks
                                                .push("terminal_chat_reply_ready=true".to_string());
                                        } else {
                                            mark_system_fail_status(
                                                &mut agent_state.status,
                                                reason.clone(),
                                            );
                                            is_lifecycle_action = true;
                                            action_output =
                                                Some(format!("Agent Failed: {}", reason));
                                        }
                                    }
                                    _ => {}
                                }

                                if success
                                    && current_tool_name == "browser__navigate"
                                    && agent_state.pending_search_completion.is_none()
                                    && should_use_web_research_path(agent_state)
                                {
                                    if let Some(url) = extract_navigation_url(&tool_args) {
                                        if is_search_results_url(&url) {
                                            let query = search_query_from_url(&url)
                                                .filter(|value| !value.trim().is_empty())
                                                .unwrap_or_else(|| agent_state.goal.clone());
                                            let extract_params = serde_jcs::to_vec(&json!({}))
                                                .or_else(|_| serde_json::to_vec(&json!({})))
                                                .unwrap_or_else(|_| b"{}".to_vec());
                                            agent_state.execution_queue.push(ActionRequest {
                                                target: ActionTarget::BrowserInspect,
                                                params: extract_params,
                                                context: ActionContext {
                                                    agent_id: "desktop_agent".to_string(),
                                                    session_id: Some(session_id),
                                                    window_id: None,
                                                },
                                                nonce: agent_state.step_count as u64 + 1,
                                            });
                                            let query_contract = {
                                                let trimmed_goal = agent_state.goal.trim();
                                                if trimmed_goal.is_empty() {
                                                    query.clone()
                                                } else {
                                                    trimmed_goal.to_string()
                                                }
                                            };
                                            let min_sources =
                                                web_pipeline_min_sources(&query_contract);
                                            agent_state.pending_search_completion =
                                                Some(PendingSearchCompletion {
                                                    query,
                                                    query_contract,
                                                    url: url.clone(),
                                                    started_step: pre_state_summary.step_index,
                                                    started_at_ms: web_pipeline_now_ms(),
                                                    deadline_ms: 0,
                                                    candidate_urls: Vec::new(),
                                                    candidate_source_hints: Vec::new(),
                                                    attempted_urls: vec![url],
                                                    blocked_urls: Vec::new(),
                                                    successful_reads: Vec::new(),
                                                    min_sources,
                                                });
                                            log::info!(
                                    "Search intent detected after browser__navigate. Queued browser__snapshot for deterministic completion."
                                );
                                        }
                                    }
                                }

                                if success
                                    && current_tool_name == "browser__snapshot"
                                    && agent_state.pending_search_completion.is_none()
                                    && history_entry
                                        .as_deref()
                                        .map(is_transient_browser_snapshot_unexpected_state)
                                        .unwrap_or(false)
                                {
                                    let bootstrap_query = agent_state.goal.clone();
                                    let queued = queue_web_search_bootstrap(
                                        agent_state,
                                        session_id,
                                        &bootstrap_query,
                                    )?;
                                    verification_checks.push(format!(
                                        "web_search_bootstrap_from_browser_snapshot={}",
                                        queued
                                    ));
                                    if queued {
                                        let note = "Browser snapshot recovery was transient; queued deterministic web__search to continue.".to_string();
                                        history_entry = Some(note.clone());
                                        action_output = Some(note);
                                    }
                                }
                            }
                            Err(TransactionError::PendingApproval(h)) => {
                                policy_decision = "require_approval".to_string();
                                let tool_jcs = serde_jcs::to_vec(&tool).unwrap();
                                let tool_hash_bytes =
                                    ioi_crypto::algorithms::hash::sha256(&tool_jcs).unwrap();
                                let mut hash_arr = [0u8; 32];
                                hash_arr.copy_from_slice(tool_hash_bytes.as_ref());

                                let action_fingerprint = sha256(&tool_jcs)
                                    .map(hex::encode)
                                    .unwrap_or_else(|_| String::new());
                                let root_retry_hash =
                                    retry_intent_hash.as_deref().unwrap_or(intent_hash.as_str());
                                if let Ok(bytes) = hex::decode(&h) {
                                    if bytes.len() == 32 {
                                        let mut decision_hash = [0u8; 32];
                                        decision_hash.copy_from_slice(&bytes);
                                        if let Some(request) = build_pii_review_request_for_tool(
                                            service,
                                            &rules,
                                            session_id,
                                            &tool,
                                            decision_hash,
                                            block_timestamp_ns / 1_000_000,
                                        )
                                        .await?
                                        {
                                            persist_pii_review_request(state, &request)?;
                                            emit_pii_review_requested(service, &request);
                                        }
                                    }
                                }
                                let incident_before = load_incident_state(state, &session_id)?;
                                let incident_stage_before = incident_before
                                    .as_ref()
                                    .map(|incident| incident.stage.clone())
                                    .unwrap_or_else(|| "None".to_string());

                                let approval_directive = register_pending_approval(
                                    state,
                                    &rules,
                                    agent_state,
                                    session_id,
                                    root_retry_hash,
                                    &current_tool_name,
                                    &tool_jcs,
                                    &action_fingerprint,
                                    &h,
                                )?;
                                let incident_after = load_incident_state(state, &session_id)?;
                                let incident_stage_after = incident_after
                                    .as_ref()
                                    .map(|incident| incident.stage.clone())
                                    .unwrap_or_else(|| "None".to_string());
                                verification_checks.push(format!(
                                    "approval_suppressed_single_pending={}",
                                    matches!(
                                        approval_directive,
                                        ApprovalDirective::SuppressDuplicatePrompt
                                    )
                                ));
                                verification_checks.push(format!(
                                    "incident_id_stable={}",
                                    match (incident_before.as_ref(), incident_after.as_ref()) {
                                        (Some(before), Some(after)) =>
                                            before.incident_id == after.incident_id,
                                        _ => true,
                                    }
                                ));
                                verification_checks.push(format!(
                                    "incident_stage_before={}",
                                    incident_stage_before
                                ));
                                verification_checks
                                    .push(format!("incident_stage_after={}", incident_stage_after));

                                agent_state.pending_tool_jcs = Some(tool_jcs);
                                agent_state.pending_tool_hash = Some(hash_arr);
                                agent_state.pending_visual_hash = Some(final_visual_phash);
                                agent_state.pending_tool_call = Some(tool_call_result.clone());
                                agent_state.last_screen_phash = Some(final_visual_phash);
                                is_gated = true;
                                is_lifecycle_action = true;
                                agent_state.status =
                                    AgentStatus::Paused("Waiting for approval".into());

                                if let Some(incident_state) =
                                    load_incident_state(state, &session_id)?
                                {
                                    if incident_state.active {
                                        log::info!(
                                "incident.approval_intercepted session={} incident_id={} root_tool={} gated_tool={}",
                                hex::encode(&session_id[..4]),
                                incident_state.incident_id,
                                incident_state.root_tool_name,
                                current_tool_name
                            );
                                    }
                                }

                                match approval_directive {
                                    ApprovalDirective::PromptUser => {
                                        let msg = format!("System: Action halted by Agency Firewall (Hash: {}). Requesting authorization.", h);
                                        let sys_msg = ioi_types::app::agentic::ChatMessage {
                                            role: "system".to_string(),
                                            content: msg,
                                            timestamp: SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .unwrap()
                                                .as_millis()
                                                as u64,
                                            trace_hash: None,
                                        };
                                        let _ = service
                                            .append_chat_to_scs(session_id, &sys_msg, block_height)
                                            .await?;
                                        success = true;
                                    }
                                    ApprovalDirective::SuppressDuplicatePrompt => {
                                        let sys_msg = ioi_types::app::agentic::ChatMessage {
                                role: "system".to_string(),
                                content:
                                    "System: Approval already pending for this incident/action. Waiting for your decision."
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
                                        success = true;
                                    }
                                    ApprovalDirective::PauseLoop => {
                                        policy_decision = "denied".to_string();
                                        success = false;
                                        let loop_msg = format!(
                                "ERROR_CLASS=PermissionOrApprovalRequired Approval loop policy paused this incident for request hash {}.",
                                h
                            );
                                        error_msg = Some(loop_msg.clone());
                                        agent_state.status = AgentStatus::Paused(
                                "Approval loop detected for the same incident/action. Automatic retries paused."
                                    .to_string(),
                            );
                                        let sys_msg = ioi_types::app::agentic::ChatMessage {
                                            role: "system".to_string(),
                                            content: format!(
                                    "System: {} Please approve, deny, or change policy settings.",
                                    loop_msg
                                ),
                                            timestamp: SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .unwrap()
                                                .as_millis()
                                                as u64,
                                            trace_hash: None,
                                        };
                                        let _ = service
                                            .append_chat_to_scs(session_id, &sys_msg, block_height)
                                            .await?;
                                    }
                                }
                            }
                            Err(e) => {
                                success = false;
                                let msg = e.to_string();
                                if msg.to_lowercase().contains("blocked by policy") {
                                    policy_decision = "denied".to_string();
                                }
                                error_msg = Some(msg.clone());
                                if !req_hash_hex.is_empty() {
                                    agent_state
                                        .tool_execution_log
                                        .insert(req_hash_hex.clone(), ToolCallStatus::Failed(msg));
                                }
                            }
                        }
                    }
                }
                }
