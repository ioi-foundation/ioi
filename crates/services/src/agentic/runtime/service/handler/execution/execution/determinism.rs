fn no_visual(
    success: bool,
    history_entry: Option<String>,
    error: Option<String>,
) -> ActionExecutionOutcome {
    (success, history_entry, error, None)
}

fn visual_observation_artifact_id(checksum: &[u8; 32]) -> String {
    format!("desktop.visual_observation.{}", hex::encode(checksum))
}

fn visual_observation_content_type(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        "image/png"
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg"
    } else {
        "application/octet-stream"
    }
}

fn persist_visual_observation(
    _service: &RuntimeAgentService,
    session_id: [u8; 32],
    block_height: u64,
    visual_observation: Vec<u8>,
) -> Result<[u8; 32], TransactionError> {
    let checksum_bytes = sha256(&visual_observation).map_err(|error| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=UnexpectedState Failed to hash visual evidence: {}",
            error
        ))
    })?;
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(checksum_bytes.as_ref());

    if let Some(memory_runtime) = _service.memory_runtime.as_ref() {
        let artifact_id = visual_observation_artifact_id(&checksum);
        let metadata_json = serde_json::to_string(&json!({
            "kind": "visual_observation",
            "artifact_id": artifact_id,
            "session_id": hex::encode(session_id),
            "block_height": block_height,
            "content_type": visual_observation_content_type(&visual_observation),
            "checksum": hex::encode(checksum),
        }))
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;

        memory_runtime
            .upsert_artifact_json(session_id, &artifact_id, &metadata_json)
            .map_err(|error| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=UnexpectedState Failed to persist visual evidence metadata: {}",
                    error
                ))
            })?;
        memory_runtime
            .put_artifact_blob(session_id, &artifact_id, &visual_observation)
            .map_err(|error| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=UnexpectedState Failed to persist visual evidence blob: {}",
                    error
                ))
            })?;
        return Ok(checksum);
    }

    Err(TransactionError::Invalid(
        "ERROR_CLASS=ToolUnavailable Visual evidence store requires a configured memory runtime."
            .to_string(),
    ))
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
    _service: &RuntimeAgentService,
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

    let target = tool.target();

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
        nonce: execution_request_nonce(agent_state, step_index),
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
