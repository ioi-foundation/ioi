use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn timer_query_routes_to_command_exec_without_planner_fast_path() -> Result<()> {
    let (tx, mut rx) = tokio::sync::broadcast::channel(256);
    let memory_runtime = build_memory_runtime();

    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(TimerIntentRuntime);
    let service = RuntimeAgentService::new_hybrid(gui, terminal, browser, runtime.clone(), runtime)
        .with_memory_runtime(memory_runtime)
        .with_event_sender(tx)
        .with_os_driver(Arc::new(NoopOsDriver));

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);

    let session_id = [0xAB; 32];
    let start_params = StartAgentParams {
        session_id,
        goal: "Set a timer for 15 minutes".to_string(),
        max_steps: 8,
        parent_session_id: None,
        initial_budget: 1000,
        mode: AgentMode::Agent,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params).map_err(anyhow::Error::msg)?,
            &mut ctx,
        )
        .await?;

    apply_policy_for_session(&mut state, session_id, default_safe_policy())?;

    while rx.try_recv().is_ok() {}

    let mut events = Vec::<KernelEvent>::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(anyhow::Error::msg)?,
                &mut ctx,
            )
            .await?;

        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }

        let agent_state = read_agent_state(&state, session_id)?;
        match agent_state.status {
            AgentStatus::Completed(_) | AgentStatus::Failed(_) | AgentStatus::Paused(_) => break,
            AgentStatus::Running | AgentStatus::Idle | AgentStatus::Terminated => {}
        }
    }

    let flush_deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    loop {
        if tokio::time::Instant::now() >= flush_deadline {
            break;
        }
        let remaining = flush_deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) => events.push(event),
            _ => break,
        }
    }

    let agent_state = read_agent_state(&state, session_id)?;
    let resolved = agent_state
        .resolved_intent
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("resolved intent missing"))?;
    assert_eq!(resolved.intent_id, "command.exec");

    assert!(
        !events.iter().any(|event| match event {
            KernelEvent::PlanReceipt(receipt) => receipt.session_id == Some(session_id),
            _ => false,
        }),
        "planner evidence should not be emitted for timer queries anymore"
    );
    assert!(
        !events.iter().any(|event| match event {
            KernelEvent::AgentActionResult {
                session_id: event_session_id,
                tool_name,
                ..
            } => *event_session_id == session_id && tool_name == "planner::execute",
            _ => false,
        }),
        "planner::execute must not run"
    );

    assert!(
        !matches!(agent_state.status, AgentStatus::Failed(_)),
        "expected non-failed status, got {:?}",
        agent_state.status
    );

    Ok(())
}
