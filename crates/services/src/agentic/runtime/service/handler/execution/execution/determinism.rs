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

fn parse_workspace_change_for_policy(
    value: serde_json::Value,
) -> Result<crate::agentic::runtime::trajectory::WorkspaceChangeRecord, TransactionError> {
    serde_json::from_value(value).map_err(|error| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Workspace change policy payload is invalid: {error}"
        ))
    })
}

fn load_workspace_changes_for_policy(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
) -> Result<Vec<crate::agentic::runtime::trajectory::WorkspaceChangeRecord>, TransactionError> {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return Ok(Vec::new());
    };

    let trajectory_changes =
        crate::agentic::runtime::utils::load_agent_trajectory_latest_checkpoint(
            memory_runtime.as_ref(),
            session_id,
        )
        .map_err(|error| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=DeterminismBoundary Failed to load workspace change checkpoint for policy: {error}"
            ))
        })?
        .map(|record| record.workspace_changes)
        .unwrap_or_default();
    if !trajectory_changes.is_empty() {
        return Ok(trajectory_changes);
    }

    crate::agentic::runtime::utils::load_agent_state_checkpoint(memory_runtime.as_ref(), session_id)
        .map_err(|error| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=DeterminismBoundary Failed to load workspace change state checkpoint for policy: {error}"
            ))
        })?
        .map(|agent_state| {
            crate::agentic::runtime::trajectory::workspace_change_records_for_state(&agent_state)
        })
        .map(Ok)
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn resolve_workspace_change_for_policy(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    change_id: Option<&str>,
    change: Option<&serde_json::Value>,
    changes: &[serde_json::Value],
) -> Result<Option<crate::agentic::runtime::trajectory::WorkspaceChangeRecord>, TransactionError> {
    let change_id = change_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    if let Some(change) = change {
        let record = parse_workspace_change_for_policy(change.clone())?;
        if let Some(change_id) = change_id.as_deref() {
            if record.change_id != change_id {
                return Err(TransactionError::Invalid(format!(
                    "ERROR_CLASS=DeterminismBoundary Workspace change policy change_id mismatch: requested '{}' but payload contains '{}'",
                    change_id, record.change_id
                )));
            }
        }
        return Ok(Some(record));
    }

    let Some(change_id) = change_id else {
        return Ok(None);
    };

    let mut available_changes = load_workspace_changes_for_policy(service, session_id)?;
    for change in changes {
        available_changes.push(parse_workspace_change_for_policy(change.clone())?);
    }

    match crate::agentic::runtime::workspace_change::find_workspace_change_by_id(
        &available_changes,
        &change_id,
    ) {
        Ok(record) => Ok(Some(record)),
        Err(error) if error.code == "change_not_found" => Ok(None),
        Err(error) => Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Workspace change policy lookup failed: {error}"
        ))),
    }
}

fn request_args_for_policy(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    tool: &AgentTool,
    mut args_value: serde_json::Value,
) -> Result<serde_json::Value, TransactionError> {
    let AgentTool::WorkspaceChangeRollback {
        change_id,
        change,
        changes,
    } = tool
    else {
        return Ok(args_value);
    };

    let Some(record) = resolve_workspace_change_for_policy(
        service,
        session_id,
        change_id.as_deref(),
        change.as_ref(),
        changes,
    )?
    else {
        return Ok(args_value);
    };
    let Some(path) = record
        .path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(args_value);
    };

    let Some(object) = args_value.as_object_mut() else {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=DeterminismBoundary Workspace change rollback policy args must be an object"
                .to_string(),
        ));
    };

    if let Some(existing_path) = object.get("path").and_then(|value| value.as_str()) {
        if existing_path.trim() != path {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=DeterminismBoundary Workspace change rollback path mismatch: policy args '{}' but record '{}'",
                existing_path, path
            )));
        }
    } else {
        object.insert(
            "path".to_string(),
            serde_json::Value::String(path.to_string()),
        );
    }
    Ok(args_value)
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
    let args_value = request_args_for_policy(_service, session_id, tool, args_value)?;
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

    let policy_hash = compute_policy_hash(rules)?;
    log::warn!(
        "CEC determinism policy hash context: session={} policy_id={} defaults={:?} rule_count={} cwd={} policy_hash={} request_hash={}",
        hex::encode(&session_id[..4]),
        rules.policy_id,
        rules.defaults,
        rules.rules.len(),
        agent_state.working_directory,
        hex::encode(&policy_hash[..6]),
        hex::encode(&request_hash[..6])
    );

    Ok(DeterminismContext {
        request,
        request_hash,
        policy_hash,
        target_str,
        tool_hash,
        intent_id: resolved_intent_id(agent_state),
        workload_spec,
        observed_domain,
        signing_context: execution_call_context.map(|ctx| (ctx.chain_id, ctx.signer_account_id)),
    })
}
