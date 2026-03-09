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

    let mcp = service
        .mcp
        .clone()
        .unwrap_or_else(|| Arc::new(McpManager::new()));

    // [VERIFIED] This line ensures the registry propagates to execution
    let lens_registry_arc = service.lens_registry.clone();

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

    // Pre-execution focus recovery for click-like tools.
    // This reduces FocusMismatch loops by verifying/repairing focus before click dispatch.
    if focus::is_focus_sensitive_tool(&tool) {
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
    if matches!(
        tool,
        AgentTool::BrowserNavigate { .. }
            | AgentTool::BrowserSnapshot { .. }
            | AgentTool::BrowserClick { .. }
            | AgentTool::BrowserClickElement { .. }
            | AgentTool::BrowserSyntheticClick { .. }
            | AgentTool::BrowserScroll { .. }
            | AgentTool::BrowserType { .. }
            | AgentTool::BrowserKey { .. }
            | AgentTool::BrowserFindText { .. }
            | AgentTool::BrowserScreenshot { .. }
            | AgentTool::BrowserWait { .. }
            | AgentTool::BrowserUploadFile { .. }
            | AgentTool::BrowserDropdownOptions { .. }
            | AgentTool::BrowserSelectDropdown { .. }
            | AgentTool::BrowserGoBack { .. }
            | AgentTool::BrowserTabList {}
            | AgentTool::BrowserTabSwitch { .. }
            | AgentTool::BrowserTabClose { .. }
    ) {
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
            if let (Some(state), Some(call_context)) =
                (execution_state.as_deref_mut(), execution_call_context)
            {
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
                if let Some(result) = try_execute_wallet_mail_dynamic_tool(
                    service,
                    state,
                    call_context,
                    &value,
                    latest_user_message_raw.as_deref(),
                    session_id,
                    step_index,
                )
                .await?
                {
                    let (success, out, err) = result;
                    return Ok(no_visual(success, out, err));
                }
            }

            if let Some(result) =
                crate::agentic::desktop::connectors::google_workspace::try_execute_dynamic_tool(
                    service,
                    agent_state,
                    session_id,
                    &value,
                )
                .await?
            {
                let (success, out, err) = result;
                return Ok(no_visual(success, out, err));
            }

            let result = executor
                .execute(
                    AgentTool::Dynamic(value),
                    session_id,
                    step_index,
                    visual_phash,
                    agent_state.visual_som_map.as_ref(),
                    agent_state.visual_semantic_map.as_ref(),
                    agent_state.active_lens.as_deref(),
                )
                .await;
            finalize_executor_result(result)
        }

        // Delegate Execution Tools
        _ => {
            let result = executor
                .execute(
                    tool,
                    session_id,
                    step_index,
                    visual_phash,
                    agent_state.visual_som_map.as_ref(),
                    agent_state.visual_semantic_map.as_ref(),
                    agent_state.active_lens.as_deref(),
                )
                .await;
            finalize_executor_result(result)
        }
    }
}
