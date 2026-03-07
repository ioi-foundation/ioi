fn no_visual(
    success: bool,
    history_entry: Option<String>,
    error: Option<String>,
) -> ActionExecutionOutcome {
    (success, history_entry, error, None)
}

fn persist_visual_observation(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    block_height: u64,
    visual_observation: Vec<u8>,
) -> Result<[u8; 32], TransactionError> {
    let scs_mutex = service.scs.as_ref().ok_or_else(|| {
        TransactionError::Invalid(
            "ERROR_CLASS=UnexpectedState Visual evidence store unavailable.".to_string(),
        )
    })?;

    let mut store = scs_mutex
        .lock()
        .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

    let frame_id = store
        .append_frame(
            FrameType::Observation,
            &visual_observation,
            block_height,
            [0u8; 32],
            session_id,
            RetentionClass::Ephemeral,
        )
        .map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=UnexpectedState Failed to persist visual evidence: {}",
                e
            ))
        })?;

    store
        .toc
        .frames
        .get(frame_id as usize)
        .map(|frame| frame.checksum)
        .ok_or_else(|| {
            TransactionError::Invalid(
                "ERROR_CLASS=UnexpectedState Persisted visual evidence frame missing.".to_string(),
            )
        })
}

fn resolved_intent_id(agent_state: &AgentState) -> String {
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.intent_id.clone())
        .unwrap_or_else(|| "resolver.unclassified".to_string())
}

fn unix_timestamp_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn build_determinism_context(
    service: &DesktopAgentService,
    tool: &AgentTool,
    rules: &ActionRules,
    agent_state: &AgentState,
    os_driver: &Arc<dyn OsDriver>,
    session_id: [u8; 32],
    step_index: u32,
    execution_call_context: Option<ServiceCallContext<'_>>,
) -> Result<DeterminismContext, TransactionError> {
    // 1. Serialization for Policy Check
    let tool_value =
        serde_json::to_value(tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let args_value = tool_value
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let request_params = serde_jcs::to_vec(&args_value)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;

    // 2. Compute Canonical Tool Bytes for Hash Stability
    let tool_jcs =
        serde_jcs::to_vec(tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Tool hash failed: {}",
            e
        ))
    })?;
    let mut tool_hash = [0u8; 32];
    tool_hash.copy_from_slice(tool_hash_bytes.as_ref());

    let mut target = tool.target();
    // `FrameType::Observation` inspection can invoke screenshot captioning; gate it via a
    // distinct policy target so default-safe rules can require explicit approval.
    if let AgentTool::MemoryInspect { frame_id } = tool {
        if let Some(scs_mutex) = service.scs.as_ref() {
            if let Ok(store) = scs_mutex.lock() {
                if let Some(frame) = store.toc.frames.get(*frame_id as usize) {
                    if matches!(frame.frame_type, FrameType::Observation) {
                        target = ioi_types::app::ActionTarget::Custom(
                            "memory::inspect_observation".to_string(),
                        );
                    }
                }
            }
        }
    }

    let window_binding =
        resolve_window_binding_for_target(os_driver, session_id, &target, "pre_determinism_commit")
            .await?;

    let request = ioi_types::app::ActionRequest {
        target: target.clone(),
        params: request_params,
        context: ioi_types::app::ActionContext {
            agent_id: "desktop_agent".into(),
            session_id: Some(session_id),
            window_id: window_binding,
        },
        nonce: step_index as u64,
    };

    let request_hash = request.try_hash().map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Invalid committed action request: {}",
            e
        ))
    })?;
    let (workload_spec, observed_domain) = build_workload_spec(
        tool,
        &target,
        request_hash,
        window_binding,
        agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.clone()),
        unix_timestamp_ms_now(),
    );

    let target_str = match &target {
        ioi_types::app::ActionTarget::Custom(s) => s.clone(),
        _ => serde_json::to_string(&target)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim_matches('"')
            .to_string(),
    };

    Ok(DeterminismContext {
        request,
        request_hash,
        policy_hash: compute_policy_hash(rules)?,
        target_str,
        tool_hash,
        intent_id: resolved_intent_id(agent_state),
        workload_spec,
        observed_domain,
        signing_context: execution_call_context.map(|ctx| (ctx.chain_id, ctx.signer_account_id)),
    })
}
