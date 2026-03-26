fn browser_tool_execution_timeout() -> Duration {
    const DEFAULT_TIMEOUT_SECS: u64 = 12;
    std::env::var("IOI_BROWSER_QUEUE_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS))
}

fn browser_tool_timeout_for_action(tool: &AgentTool) -> Option<Duration> {
    const WAIT_GRACE_MS: u64 = 5_000;

    if !matches!(
        tool.target(),
        ActionTarget::BrowserInteract | ActionTarget::BrowserInspect
    ) {
        return None;
    }

    let baseline = browser_tool_execution_timeout();
    Some(match tool {
        AgentTool::BrowserWait { ms, timeout_ms, .. } => {
            let requested_ms = ms.or(*timeout_ms).unwrap_or(0);
            Duration::from_millis(requested_ms.saturating_add(WAIT_GRACE_MS)).max(baseline)
        }
        _ => baseline,
    })
}

fn browser_tool_name(tool: &AgentTool) -> Option<&'static str> {
    match tool {
        AgentTool::BrowserNavigate { .. } => Some("browser__navigate"),
        AgentTool::BrowserSnapshot { .. } => Some("browser__snapshot"),
        AgentTool::BrowserClick { .. } => Some("browser__click"),
        AgentTool::BrowserClickElement { .. } => Some("browser__click_element"),
        AgentTool::BrowserHover { .. } => Some("browser__hover"),
        AgentTool::BrowserMoveMouse { .. } => Some("browser__move_mouse"),
        AgentTool::BrowserMouseDown { .. } => Some("browser__mouse_down"),
        AgentTool::BrowserMouseUp { .. } => Some("browser__mouse_up"),
        AgentTool::BrowserSyntheticClick { .. } => Some("browser__synthetic_click"),
        AgentTool::BrowserScroll { .. } => Some("browser__scroll"),
        AgentTool::BrowserType { .. } => Some("browser__type"),
        AgentTool::BrowserSelectText { .. } => Some("browser__select_text"),
        AgentTool::BrowserKey { .. } => Some("browser__key"),
        AgentTool::BrowserCopySelection {} => Some("browser__copy_selection"),
        AgentTool::BrowserPasteClipboard { .. } => Some("browser__paste_clipboard"),
        AgentTool::BrowserFindText { .. } => Some("browser__find_text"),
        AgentTool::BrowserCanvasSummary { .. } => Some("browser__canvas_summary"),
        AgentTool::BrowserScreenshot { .. } => Some("browser__screenshot"),
        AgentTool::BrowserWait { .. } => Some("browser__wait"),
        AgentTool::BrowserUploadFile { .. } => Some("browser__upload_file"),
        AgentTool::BrowserDropdownOptions { .. } => Some("browser__dropdown_options"),
        AgentTool::BrowserSelectDropdown { .. } => Some("browser__select_dropdown"),
        AgentTool::BrowserGoBack { .. } => Some("browser__go_back"),
        AgentTool::BrowserTabList {} => Some("browser__tab_list"),
        AgentTool::BrowserTabSwitch { .. } => Some("browser__tab_switch"),
        AgentTool::BrowserTabClose { .. } => Some("browser__tab_close"),
        _ => None,
    }
}

pub async fn handle_action_execution(
    service: &DesktopAgentService,
    tool: AgentTool,
    session_id: [u8; 32],
    step_index: u32,
    visual_phash: [u8; 32],
    rules: &ActionRules,
    agent_state: &AgentState,
    os_driver: &Arc<dyn OsDriver>,
    scoped_exception_hash: Option<[u8; 32]>,
    mut execution_state: Option<&mut dyn StateAccess>,
    execution_call_context: Option<ServiceCallContext<'_>>,
) -> Result<ActionExecutionOutcome, TransactionError> {
    let mut tool = tool;
    let execution_started = Instant::now();
    let intent_id = resolved_intent_id(agent_state);

    let mcp = service
        .mcp
        .clone()
        .unwrap_or_else(|| Arc::new(McpManager::new()));

    // [VERIFIED] This line ensures the registry propagates to execution
    let lens_registry_arc = service.lens_registry.clone();

    let prepare_started = Instant::now();
    let (mut foreground_window, target_app_hint) = prepare_tool_for_execution(
        service,
        &mut tool,
        rules,
        session_id,
        agent_state,
        os_driver,
        scoped_exception_hash,
    )
    .await?;
    emit_execution_phase_timing_receipt(
        service,
        session_id,
        step_index,
        &intent_id,
        "service_prepare_tool",
        prepare_started,
        true,
        "completed",
        json!({
            "tool_target": format!("{:?}", tool.target()),
            "target_app_hint": target_app_hint.clone(),
            "foreground_window_bound": foreground_window.is_some(),
        }),
    );

    let determinism_started = Instant::now();
    let determinism = build_determinism_context(
        service,
        &tool,
        rules,
        agent_state,
        os_driver,
        session_id,
        step_index,
        execution_call_context,
    )
    .await?;
    emit_execution_phase_timing_receipt(
        service,
        session_id,
        step_index,
        &intent_id,
        "service_determinism_context",
        determinism_started,
        true,
        "completed",
        json!({
            "runtime_target": determinism.workload_spec.runtime_target.as_label(),
            "net_mode": determinism.workload_spec.net_mode.as_label(),
            "request_target": format!("{:?}", determinism.request.target),
            "observed_domain": determinism.observed_domain.clone(),
        }),
    );

    let policy_started = Instant::now();
    enforce_policy_and_record(
        service,
        &tool,
        rules,
        agent_state,
        os_driver,
        session_id,
        step_index,
        &mut execution_state,
        &determinism,
    )
    .await?;
    emit_execution_phase_timing_receipt(
        service,
        session_id,
        step_index,
        &determinism.intent_id,
        "service_policy_gate",
        policy_started,
        true,
        "completed",
        json!({
            "runtime_target": determinism.workload_spec.runtime_target.as_label(),
            "net_mode": determinism.workload_spec.net_mode.as_label(),
        }),
    );

    // Pre-execution focus recovery for click-like tools.
    // This reduces FocusMismatch loops by verifying/repairing focus before click dispatch.
    if focus::is_focus_sensitive_tool(&tool) {
        let focus_started = Instant::now();
        if let Some(hint) = target_app_hint
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
        {
            if !focus::window_matches_hint(foreground_window.as_ref(), hint) {
                match os_driver.focus_window(hint).await {
                    Ok(true) => {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        foreground_window =
                            query_active_window_with_timeout(os_driver, session_id, "post_focus")
                                .await;
                        if !focus::window_matches_hint(foreground_window.as_ref(), hint) {
                            return Ok(no_visual(
                                false,
                                None,
                                Some(format!(
                                    "ERROR_CLASS=FocusMismatch Focused window still does not match target '{}'.",
                                    hint
                                )),
                            ));
                        }
                    }
                    Ok(false) => {
                        return Ok(no_visual(
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=FocusMismatch Unable to focus target window '{}'.",
                                hint
                            )),
                        ));
                    }
                    Err(e) => {
                        let err = e.to_string();
                        if focus::is_missing_focus_dependency_error(&err) {
                            return Ok(no_visual(
                                false,
                                None,
                                Some(format!(
                                    "ERROR_CLASS=MissingDependency Focus dependency unavailable while focusing '{}': {}",
                                    hint, err
                                )),
                            ));
                        }
                        return Ok(no_visual(
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=FocusMismatch Focus attempt failed for '{}': {}",
                                hint, err
                            )),
                        ));
                    }
                }
            }
        }
        emit_execution_phase_timing_receipt(
            service,
            session_id,
            step_index,
            &determinism.intent_id,
            "service_focus_recovery",
            focus_started,
            true,
            "completed",
            json!({
                "hint": target_app_hint.clone(),
                "focused_window_bound": foreground_window.is_some(),
            }),
        );
    }

    // Construct executor locally with all dependencies after focus recovery.
    let executor = ToolExecutor::new(
        service.gui.clone(),
        os_driver.clone(),
        service.terminal.clone(),
        service.browser.clone(),
        mcp,
        service.event_sender.clone(),
        Some(lens_registry_arc),
        service.reasoning_inference.clone(), // Pass reasoning engine for visual search
        Some(service.scrubber.clone()),
    )
    .with_window_context(
        foreground_window.clone(),
        target_app_hint.clone(),
        Some(agent_state.current_tier),
    )
    .with_expected_visual_hash(Some(visual_phash))
    .with_workload_spec(Some(determinism.workload_spec.clone()))
    .with_working_directory(Some(agent_state.working_directory.clone()));

    // Explicitly acquire lease for browser tools
    if browser_tool_name(&tool).is_some() {
        service.browser.set_lease(true);
    }

    let finalize_executor_result =
        |result: crate::agentic::desktop::execution::ToolExecutionResult| {
            let visual_hash = if let Some(visual_observation) = result.visual_observation {
                let block_height = execution_call_context
                    .map(|ctx| ctx.block_height)
                    .ok_or_else(|| {
                        TransactionError::Invalid(
                        "ERROR_CLASS=UnexpectedState Missing execution context for visual evidence."
                            .to_string(),
                    )
                    })?;
                Some(persist_visual_observation(
                    service,
                    session_id,
                    block_height,
                    visual_observation,
                )?)
            } else {
                None
            };

            Ok((
                result.success,
                result.history_entry,
                result.error,
                visual_hash,
            ))
        };

    // 5. Handle Meta-Tools and Execution
    match tool {
        AgentTool::SystemFail {
            reason,
            missing_capability,
        } => Ok(handlers::handle_system_fail_tool(
            service,
            session_id,
            step_index,
            reason,
            missing_capability,
        )),
        AgentTool::MemorySearch { query } => {
            Ok(handlers::handle_memory_search_tool(service, session_id, step_index, &query).await)
        }
        AgentTool::MemoryInspect { frame_id } => {
            Ok(handlers::handle_memory_inspect_tool(service, frame_id).await)
        }
        AgentTool::MemoryReplaceCore { section, content } => Ok(
            handlers::handle_memory_replace_core_tool(service, session_id, &section, &content)
                .await,
        ),
        AgentTool::MemoryAppendCore { section, content } => Ok(
            handlers::handle_memory_append_core_tool(service, session_id, &section, &content)
                .await,
        ),
        AgentTool::MemoryClearCore { section } => {
            Ok(handlers::handle_memory_clear_core_tool(service, session_id, &section).await)
        }
        AgentTool::AgentDelegate { goal, budget } => {
            Ok(handlers::handle_agent_delegate_tool(goal, budget))
        }
        AgentTool::AgentAwait { .. } => Ok(handlers::handle_agent_await_tool()),
        AgentTool::AgentPause { .. } => Ok(handlers::handle_agent_pause_tool()),
        AgentTool::AgentComplete { .. } => Ok(handlers::handle_agent_complete_tool()),
        AgentTool::CommerceCheckout { .. } => Ok(handlers::handle_commerce_checkout_tool()),
        AgentTool::ChatReply { message } => Ok(handlers::handle_chat_reply_tool(message)),
        AgentTool::AutomationCreateMonitor {
            title,
            description,
            keywords,
            interval_seconds,
            source_prompt,
        } => Ok(handlers::handle_automation_create_monitor_tool(
            Some(&service.workspace_path),
            title,
            description,
            keywords,
            interval_seconds,
            source_prompt,
        )),
        AgentTool::OsFocusWindow { title } => {
            Ok(handlers::handle_os_focus_window_tool(os_driver, title).await)
        }
        AgentTool::OsCopy { content } => {
            Ok(handlers::handle_os_copy_tool(os_driver, content).await)
        }
        AgentTool::OsPaste {} => Ok(handlers::handle_os_paste_tool(os_driver).await),
        AgentTool::Dynamic(value) => {
            let latest_user_message_raw = service
                .hydrate_session_history_raw(agent_state.session_id)
                .ok()
                .and_then(|history| {
                    history
                        .iter()
                        .rfind(|message| message.role == "user")
                        .map(|message| message.content.clone())
                })
                .or_else(|| {
                    let goal = agent_state.goal.trim();
                    if goal.is_empty() {
                        None
                    } else {
                        Some(goal.to_string())
                    }
                });
            let adapter_state = execution_state.take();
            if let Some(result) = adapters::execute_dynamic_tool(
                service,
                &value,
                session_id,
                step_index,
                &determinism.workload_spec,
                agent_state,
                adapter_state,
                execution_call_context,
                latest_user_message_raw.as_deref(),
            )
            .await?
            {
                return Ok(no_visual(
                    result.success,
                    result.history_entry,
                    result.error,
                ));
            }

            Ok(no_visual(
                false,
                None,
                Some(format!(
                    "ERROR_CLASS=UnsupportedTool No adapter admitted dynamic tool '{}'",
                    value
                        .get("name")
                        .and_then(|entry| entry.as_str())
                        .unwrap_or("unknown")
                )),
            ))
        }

        // Delegate Execution Tools
        _ => {
            let browser_timeout = browser_tool_timeout_for_action(&tool);
            let has_browser_timeout = browser_timeout.is_some();
            let browser_tool_name = browser_tool_name(&tool).map(str::to_string);
            let executor_started = Instant::now();
            let result = if let Some(timeout_duration) = browser_timeout {
                match tokio::time::timeout(
                    timeout_duration,
                    executor.execute(
                        tool,
                        session_id,
                        step_index,
                        visual_phash,
                        agent_state.visual_som_map.as_ref(),
                        agent_state.visual_semantic_map.as_ref(),
                        agent_state.active_lens.as_deref(),
                    ),
                )
                .await
                {
                    Ok(result) => {
                        emit_execution_phase_timing_receipt(
                            service,
                            session_id,
                            step_index,
                            &determinism.intent_id,
                            "service_executor_dispatch",
                            executor_started,
                            true,
                            "completed",
                            json!({
                                "tool_name": browser_tool_name.clone(),
                                "timeout_ms": timeout_duration.as_millis() as u64,
                                "runtime_target": determinism.workload_spec.runtime_target.as_label(),
                            }),
                        );
                        result
                    }
                    Err(_) => {
                        emit_execution_phase_timing_receipt(
                            service,
                            session_id,
                            step_index,
                            &determinism.intent_id,
                            "service_executor_dispatch",
                            executor_started,
                            false,
                            "timeout",
                            json!({
                                "tool_name": browser_tool_name.clone(),
                                "timeout_ms": timeout_duration.as_millis() as u64,
                                "runtime_target": determinism.workload_spec.runtime_target.as_label(),
                            }),
                        );
                        emit_execution_phase_timing_receipt(
                            service,
                            session_id,
                            step_index,
                            &determinism.intent_id,
                            "service_action_complete",
                            execution_started,
                            false,
                            "timeout",
                            json!({
                                "tool_name": browser_tool_name.clone(),
                                "runtime_target": determinism.workload_spec.runtime_target.as_label(),
                            }),
                        );
                        return Ok(no_visual(
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=TimeoutOrHang Browser tool '{}' timed out after {}ms.",
                                browser_tool_name.as_deref().unwrap_or("browser"),
                                timeout_duration.as_millis()
                            )),
                        ));
                    }
                }
            } else {
                executor
                    .execute(
                        tool,
                        session_id,
                        step_index,
                        visual_phash,
                        agent_state.visual_som_map.as_ref(),
                        agent_state.visual_semantic_map.as_ref(),
                        agent_state.active_lens.as_deref(),
                    )
                    .await
            };
            if !has_browser_timeout {
                emit_execution_phase_timing_receipt(
                    service,
                    session_id,
                    step_index,
                    &determinism.intent_id,
                    "service_executor_dispatch",
                    executor_started,
                    true,
                    "completed",
                    json!({
                        "tool_name": browser_tool_name.clone(),
                        "runtime_target": determinism.workload_spec.runtime_target.as_label(),
                    }),
                );
            }
            let finalize_started = Instant::now();
            let finalized_result = finalize_executor_result(result);
            emit_execution_phase_timing_receipt(
                service,
                session_id,
                step_index,
                &determinism.intent_id,
                "service_finalize_executor_result",
                finalize_started,
                finalized_result.is_ok(),
                if finalized_result.is_ok() {
                    "completed"
                } else {
                    "error"
                },
                json!({
                    "tool_name": browser_tool_name.clone(),
                    "runtime_target": determinism.workload_spec.runtime_target.as_label(),
                }),
            );
            emit_execution_phase_timing_receipt(
                service,
                session_id,
                step_index,
                &determinism.intent_id,
                "service_action_complete",
                execution_started,
                finalized_result.is_ok(),
                if finalized_result.is_ok() {
                    "completed"
                } else {
                    "error"
                },
                json!({
                    "tool_name": browser_tool_name.clone(),
                    "runtime_target": determinism.workload_spec.runtime_target.as_label(),
                }),
            );
            finalized_result
        }
    }
}
