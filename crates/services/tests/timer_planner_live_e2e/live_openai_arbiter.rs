use super::*;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live external inference required for OpenAI timer e2e arbiter"]
async fn timer_query_live_openai_e2e_with_model_arbiter() -> Result<()> {
    load_env_from_workspace_dotenv_if_present();
    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow::anyhow!("OPENAI_API_KEY is required for live e2e"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        OPENAI_CHAT_COMPLETIONS_URL.to_string(),
        openai_api_key,
        openai_model,
    ));

    let facets = QueryFacets::from_query(LIVE_TIMER_QUERY);
    let start = Instant::now();

    let (tx, mut rx) = tokio::sync::broadcast::channel(512);
    let memory_runtime = build_memory_runtime();

    let service = RuntimeAgentService::new_hybrid(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    )
    .with_memory_runtime(memory_runtime)
    .with_event_sender(tx)
    .with_os_driver(Arc::new(NoopOsDriver));

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = [0xCD; 32];

    tokio::time::timeout(
        LIVE_SERVICE_CALL_TIMEOUT,
        service.handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&StartAgentParams {
                session_id,
                goal: LIVE_TIMER_QUERY.to_string(),
                max_steps: 10,
                parent_session_id: None,
                initial_budget: 1600,
                mode: AgentMode::Agent,
            })
            .map_err(anyhow::Error::msg)?,
            &mut ctx,
        ),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "live e2e call timed out: method=start@v1 timeout_secs={}",
            LIVE_SERVICE_CALL_TIMEOUT.as_secs()
        )
    })?
    .map_err(anyhow::Error::msg)?;

    let mut live_rules = default_safe_policy();
    live_rules.rules.insert(
        0,
        Rule {
            rule_id: Some("require-approval-sys-exec-live-e2e".to_string()),
            target: "sys::exec".to_string(),
            conditions: Default::default(),
            action: Verdict::RequireApproval,
        },
    );
    live_rules.rules.push(Rule {
        rule_id: Some("block-install-package-live-e2e".to_string()),
        target: "sys::install_package".to_string(),
        conditions: Default::default(),
        action: Verdict::Block,
    });
    apply_policy_for_session(&mut state, session_id, live_rules)?;

    let deadline = tokio::time::Instant::now() + LIVE_STEP_DEADLINE;
    let mut events = Vec::<KernelEvent>::new();
    let mut auto_resume_count = 0usize;
    while tokio::time::Instant::now() < deadline {
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        let agent_state = read_agent_state(&state, session_id)?;
        match &agent_state.status {
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => break,
            AgentStatus::Paused(reason) => {
                let waiting_for_approval = reason.to_ascii_lowercase().contains("approval");
                if !waiting_for_approval {
                    break;
                }
                if auto_resume_count >= LIVE_MAX_AUTO_APPROVAL_RESUMES {
                    break;
                }
                let request_hash = agent_state.pending_tool_hash.ok_or_else(|| {
                    anyhow::anyhow!("pending approval hash missing during live auto-resume")
                })?;
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let policy_hash = active_policy_hash_for_session(&state, session_id)?;
                let (authority, approval_grant) = build_approval_grant_for_resume(
                    session_id,
                    request_hash,
                    policy_hash,
                    now_ms,
                    agent_state.pending_visual_hash,
                )?;
                service
                    .handle_service_call(
                        &mut state,
                        "register_approval_authority@v1",
                        &codec::to_bytes_canonical(&RegisterApprovalAuthorityParams { authority })
                            .map_err(anyhow::Error::msg)?,
                        &mut ctx,
                    )
                    .await
                    .map_err(anyhow::Error::msg)?;
                tokio::time::timeout(
                    LIVE_SERVICE_CALL_TIMEOUT,
                    service.handle_service_call(
                        &mut state,
                        "resume@v1",
                        &codec::to_bytes_canonical(&ResumeAgentParams {
                            session_id,
                            approval_grant: Some(approval_grant),
                        })
                        .map_err(anyhow::Error::msg)?,
                        &mut ctx,
                    ),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "live e2e call timed out: method=resume@v1 timeout_secs={}",
                        LIVE_SERVICE_CALL_TIMEOUT.as_secs()
                    )
                })?
                .map_err(anyhow::Error::msg)?;
                auto_resume_count = auto_resume_count.saturating_add(1);
                continue;
            }
            AgentStatus::Running | AgentStatus::Idle | AgentStatus::Terminated => {}
        }
        tokio::time::timeout(
            LIVE_SERVICE_CALL_TIMEOUT,
            service.handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(anyhow::Error::msg)?,
                &mut ctx,
            ),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "live e2e call timed out: method=step@v1 timeout_secs={}",
                LIVE_SERVICE_CALL_TIMEOUT.as_secs()
            )
        })?
        .map_err(anyhow::Error::msg)?;
    }

    let drain_deadline = tokio::time::Instant::now() + LIVE_EVENT_DRAIN_WINDOW;
    while tokio::time::Instant::now() < drain_deadline {
        let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) => events.push(event),
            _ => break,
        }
    }

    let elapsed = start.elapsed();
    let agent_state = read_agent_state(&state, session_id)?;
    let final_message = match &agent_state.status {
        AgentStatus::Completed(Some(text)) => Some(text.clone()),
        _ => None,
    };
    let pending_tool = agent_state
        .pending_tool_jcs
        .as_ref()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(raw).ok());
    let deterministic_checks = build_deterministic_checks(
        &facets,
        &events,
        session_id,
        elapsed,
        &agent_state.status,
        final_message.as_deref(),
    );
    let routing_checks_raw = routing_verification_checks(&events, session_id);
    let routing_checks_arbiter = routing_verification_checks_for_arbiter(&routing_checks_raw);

    let evidence_payload = json!({
        "query_facets": facets,
        "agent_status": format!("{:?}", agent_state.status),
        "final_reply": final_message,
        "pending_tool": pending_tool,
        "elapsed_ms": elapsed.as_millis(),
        "deterministic_checks": deterministic_checks,
        "action_tools": action_tool_names(&events, session_id),
        "sys_exec_command_previews": sys_exec_command_previews(&events, session_id),
        "successful_sys_exec_fingerprints": successful_sys_exec_fingerprints(&events, session_id),
        "approval_require_counts": approval_require_counts(&events, session_id),
        "routing_verification_checks_raw": routing_checks_raw,
        "routing_verification_checks_arbiter": routing_checks_arbiter,
        "auto_resume_count": auto_resume_count,
    });

    let arbiter_prompt = format!(
        "Evaluate timer-query quality for query_id={query_id}.\n\
Return strict JSON only with schema:\n\
{{\"pass\": bool, \"confidence\": \"high|medium|low\", \"rationale\": \"string\", \"failures\": [string]}}\n\
Fail if:\n\
1) final reply does not directly answer the query,\n\
2) claims are unsupported by evidence,\n\
3) output quality depends on lexical phrase artifacts instead of facet/evidence grounding,\n\
	4) capability lifecycle evidence is incomplete (missing route/discovery/execution/verification),\n\
	5) final reply lacks structured evidence fields (`Run timestamp (UTC)`, `Target UTC`, `Mechanism`),\n\
	6) CEC markers are incomplete (missing any required `evidence::...=true` or `success_condition::...=true`, including notification-path evidence for timer goals),\n\
	7) `Target UTC` is earlier than `Run timestamp (UTC)` or does not reflect the requested 15-minute delay,\n\
	8) identical approval-gated command fingerprints are repeated instead of progressing state,\n\
	9) no user-visible or audible notification path is armed for timer completion,\n\
	10) no delayed timer backend is armed (for example `sleep`, scheduler, or equivalent delayed execution primitive),\n\
	11) notification evidence is immediate-only and not deferred/scheduled for timer due time.\n\
	Use `routing_verification_checks_arbiter` for normalized final-state contract evidence; treat `routing_verification_checks_raw` as transient trace.\n\
Evidence JSON:\n{evidence}",
        query_id = QueryFacets::from_query(LIVE_TIMER_QUERY).query_id,
        evidence = serde_json::to_string_pretty(&evidence_payload)?,
    );

    let arbiter_raw = tokio::time::timeout(
        LIVE_ARBITER_INFERENCE_TIMEOUT,
        runtime.execute_inference(
            [0u8; 32],
            arbiter_prompt.as_bytes(),
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: 260,
                ..Default::default()
            },
        ),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "live e2e arbiter timed out after {} seconds",
            LIVE_ARBITER_INFERENCE_TIMEOUT.as_secs()
        )
    })?
    .map_err(anyhow::Error::msg)?;
    let arbiter_raw_text = String::from_utf8_lossy(&arbiter_raw).trim().to_string();
    let arbiter_verdict = parse_arbiter_verdict(&arbiter_raw_text)?;

    let deterministic_pass = evidence_payload["deterministic_checks"]["failures"]
        .as_array()
        .map(|items| items.is_empty())
        .unwrap_or(false);
    println!(
        "timer_live_e2e_evidence={}",
        serde_json::to_string_pretty(&evidence_payload)?
    );
    println!(
        "timer_live_e2e_arbiter={}",
        serde_json::to_string(&arbiter_verdict)?
    );
    assert!(
        deterministic_pass,
        "deterministic checks failed: {}",
        serde_json::to_string_pretty(&evidence_payload)?
    );
    assert!(
        arbiter_verdict.pass,
        "arbiter rejected run: {} | evidence={}",
        serde_json::to_string(&arbiter_verdict)?,
        serde_json::to_string_pretty(&evidence_payload)?
    );

    Ok(())
}
