pub async fn connector_run_action(
    connector_id: &str,
    action_id: &str,
    input: Value,
) -> Result<ConnectorActionResult, String> {
    if !matches_google_connector_id(connector_id) {
        return Err(format!("Unsupported connector '{}'", connector_id));
    }

    let spec = find_action_by_id(action_id)
        .ok_or_else(|| format!("Unsupported Google connector action '{}'", action_id))?;
    let normalized_input = normalize_google_action_input(&spec, &input).await?;
    let args = build_google_workspace_args(&spec, &normalized_input)?;
    let output = run_gws_command(
        &args,
        command_timeout_secs_for_action(spec.id),
        spec.required_scopes,
    )
    .await?;
    let data = parse_jsonish_output(&output.stdout);
    let summary = summarize_action(&spec, &data, &normalized_input);

    Ok(ConnectorActionResult {
        connector_id: GOOGLE_CONNECTOR_ID.to_string(),
        action_id: spec.id.to_string(),
        tool_name: spec.tool_name.to_string(),
        provider: GOOGLE_CONNECTOR_PROVIDER.to_string(),
        summary,
        data,
        raw_output: Some(output.stdout),
        executed_at_utc: now_rfc3339(),
    })
}

pub async fn try_execute_dynamic_tool(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    session_id: [u8; 32],
    raw_json: &Value,
) -> Result<Option<(bool, Option<String>, Option<String>)>, TransactionError> {
    let result = execute_dynamic_tool_as_result(service, agent_state, session_id, raw_json).await?;
    let Some(result) = result else {
        return Ok(None);
    };
    let payload = serde_json::to_string_pretty(&result.data).unwrap_or_default();
    let history = if payload.is_empty() || payload == "null" {
        result.summary
    } else {
        format!("{}\n\n{}", result.summary, payload)
    };
    Ok(Some((true, Some(history), None)))
}

pub(crate) async fn execute_dynamic_tool_as_result(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    session_id: [u8; 32],
    raw_json: &Value,
) -> Result<Option<ConnectorActionResult>, TransactionError> {
    let Some(tool_name) = raw_json.get("name").and_then(Value::as_str) else {
        return Ok(None);
    };
    let normalized = tool_name.trim().to_ascii_lowercase();
    let Some(spec) = find_action_by_tool_name(&normalized) else {
        return Ok(None);
    };

    let arguments = parse_dynamic_arguments(raw_json);
    let runtime_resume_approval =
        runtime_resume_already_authorizes_google_tool(agent_state, raw_json);
    enforce_google_tool_shield_policy(
        service,
        agent_state,
        session_id,
        &spec,
        &arguments,
        runtime_resume_approval,
    )?;

    connector_run_action(GOOGLE_CONNECTOR_ID, spec.id, arguments)
        .await
        .map(Some)
        .map_err(|error| {
            TransactionError::Invalid(format!("Google connector action failed: {}", error))
        })
}

