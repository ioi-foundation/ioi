pub fn capability_route_label(tool: &AgentTool) -> Option<&'static str> {
    match tool {
        AgentTool::SysInstallPackage { .. } => Some("enablement_request"),
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. } => Some("script_backend"),
        _ => match tool.target() {
            ActionTarget::WindowFocus
            | ActionTarget::ClipboardWrite
            | ActionTarget::ClipboardRead
            | ActionTarget::BrowserInteract
            | ActionTarget::BrowserInspect
            | ActionTarget::GuiClick
            | ActionTarget::GuiType
            | ActionTarget::GuiScroll
            | ActionTarget::GuiInspect => Some("native_integration"),
            _ => None,
        },
    }
}

pub fn extract_error_class_token(error: Option<&str>) -> Option<&str> {
    let raw = error?;
    let marker = "ERROR_CLASS=";
    let start = raw.find(marker)?;
    raw[start + marker.len()..]
        .split_whitespace()
        .next()
        .filter(|token| !token.trim().is_empty())
}

pub fn is_cec_terminal_error(error: Option<&str>) -> bool {
    matches!(
        extract_error_class_token(error),
        Some(
            "ExecutionContractViolation"
                | "DiscoveryMissing"
                | "SynthesisFailed"
                | "ExecutionFailedTerminal"
                | "VerificationMissing"
                | "PostconditionFailed"
        )
    )
}

pub fn execution_contract_violation_error(missing_keys: &str) -> String {
    let mut missing_receipts = Vec::<String>::new();
    let mut missing_postconditions = Vec::<String>::new();
    for token in missing_keys
        .split(',')
        .map(|token| token.trim())
        .filter(|token| !token.is_empty())
    {
        if let Some(rest) = token.strip_prefix("receipt::") {
            missing_receipts.push(rest.trim_end_matches("=true").to_string());
        } else if let Some(rest) = token.strip_prefix("postcondition::") {
            missing_postconditions.push(rest.trim_end_matches("=true").to_string());
        }
    }

    let (error_class, failed_stage) = if missing_receipts
        .iter()
        .any(|receipt| receipt == "host_discovery")
    {
        ("DiscoveryMissing", "discovery")
    } else if missing_receipts
        .iter()
        .any(|receipt| receipt == "provider_selection" || receipt == "provider_selection_commit")
    {
        ("SynthesisFailed", "provider_selection")
    } else if missing_receipts
        .iter()
        .any(|receipt| receipt == "verification" || receipt == "verification_commit")
    {
        ("VerificationMissing", "verification")
    } else if !missing_postconditions.is_empty() {
        ("PostconditionFailed", "completion_gate")
    } else {
        ("ExecutionContractViolation", "completion_gate")
    };

    let missing_receipts_str = if missing_receipts.is_empty() {
        "none".to_string()
    } else {
        missing_receipts.join("|")
    };
    let missing_postconditions_str = if missing_postconditions.is_empty() {
        "none".to_string()
    } else {
        missing_postconditions.join("|")
    };

    format!(
        "ERROR_CLASS={} base_error_class=ExecutionContractViolation Execution contract unmet. failed_stage={} missing_receipts={} missing_postconditions={} missing_keys={}",
        error_class, failed_stage, missing_receipts_str, missing_postconditions_str, missing_keys
    )
}

pub fn requires_timer_notification_contract(agent_state: &AgentState) -> bool {
    has_execution_receipt(
        &agent_state.tool_execution_log,
        TIMER_NOTIFICATION_CONTRACT_REQUIRED_RECEIPT,
    ) || latest_timer_backend_history_entry(agent_state).is_some()
}

pub fn is_system_clock_read_contract_intent(agent_state: &AgentState) -> bool {
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.intent_id == "system.clock.read")
        .unwrap_or(false)
}

pub fn sys_exec_satisfies_clock_read_contract(tool: &AgentTool) -> bool {
    let Some(command_preview) = sys_exec_command_preview(tool) else {
        return false;
    };
    let tokens = command_preview_tokens(&command_preview);
    if tokens.is_empty() {
        return false;
    }
    let has_clock_token = tokens.iter().any(|token| {
        CLOCK_PAYLOAD_COMMAND_TOKENS
            .iter()
            .any(|allowed| token == allowed)
    });
    if !has_clock_token {
        return false;
    }
    !tokens.iter().any(|token| {
        CLOCK_PAYLOAD_NETWORK_TOKENS
            .iter()
            .any(|blocked| token == blocked)
    })
}

pub fn record_timer_notification_contract_requirement(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    verification_checks: &mut Vec<String>,
) {
    mark_execution_receipt(
        tool_execution_log,
        TIMER_NOTIFICATION_CONTRACT_REQUIRED_RECEIPT,
    );
    verification_checks.push(receipt_marker(TIMER_NOTIFICATION_CONTRACT_REQUIRED_RECEIPT));
}

fn canonical_contract_markers(markers: &[String]) -> Vec<String> {
    let mut normalized = Vec::<String>::new();
    for marker in markers.iter().map(|value| value.trim()) {
        if marker.is_empty() {
            continue;
        }
        append_unique_marker(&mut normalized, marker);
    }
    normalized
}

fn required_markers_from_matrix(
    intent_id: &str,
    matrix: &[IntentMatrixEntry],
) -> Option<(Vec<String>, Vec<String>)> {
    let entry = matrix
        .iter()
        .find(|entry| entry.intent_id.trim() == intent_id.trim())?;
    Some((
        canonical_contract_markers(&entry.required_receipts),
        canonical_contract_markers(&entry.required_postconditions),
    ))
}

fn resolved_contract_requirements(
    agent_state: &AgentState,
    matrix: Option<&[IntentMatrixEntry]>,
) -> (Vec<String>, Vec<String>) {
    let command_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
        .unwrap_or(false);
    let resolved_from_matrix = agent_state.resolved_intent.as_ref().and_then(|resolved| {
        matrix.and_then(|entries| required_markers_from_matrix(&resolved.intent_id, entries))
    });

    let mut required_receipts = resolved_from_matrix
        .as_ref()
        .map(|(receipts, _)| receipts.clone())
        .unwrap_or_default();
    let mut required_postconditions = resolved_from_matrix
        .map(|(_, postconditions)| postconditions)
        .unwrap_or_default();

    if required_receipts.is_empty() && required_postconditions.is_empty() && command_scope {
        append_unique_marker(&mut required_receipts, "host_discovery");
        for receipt in COMMAND_SCOPE_REQUIRED_RECEIPTS {
            append_unique_marker(&mut required_receipts, receipt);
        }
        for postcondition in COMMAND_SCOPE_REQUIRED_POSTCONDITIONS {
            append_unique_marker(&mut required_postconditions, postcondition);
        }
    }

    for rrsa_receipt in rrsa_required_receipts(agent_state) {
        append_unique_marker(&mut required_receipts, &rrsa_receipt);
    }
    if agent_state.pending_search_completion.is_some() {
        append_unique_marker(&mut required_receipts, WEB_PIPELINE_TERMINAL_RECEIPT);
    }

    (required_receipts, required_postconditions)
}

fn collect_missing_contract_markers(
    agent_state: &AgentState,
    required_receipts: &[String],
    required_postconditions: &[String],
) -> Vec<String> {
    let mut missing = Vec::<String>::new();
    for receipt in required_receipts {
        if !has_execution_receipt(&agent_state.tool_execution_log, receipt) {
            push_unique_missing(&mut missing, receipt_marker(receipt));
            continue;
        }
        let receipt_value = execution_receipt_value(&agent_state.tool_execution_log, receipt)
            .unwrap_or_default()
            .trim()
            .to_string();
        if receipt_value.is_empty() {
            push_unique_missing(&mut missing, receipt_marker(receipt));
            continue;
        }
        if receipt_requires_commit_hash(receipt) && !receipt_value.starts_with("sha256:") {
            push_unique_missing(&mut missing, receipt_marker(receipt));
        }
    }

    for postcondition in required_postconditions {
        if !has_execution_postcondition(&agent_state.tool_execution_log, postcondition) {
            push_unique_missing(&mut missing, postcondition_marker(postcondition));
        }
    }

    if is_system_clock_read_contract_intent(agent_state)
        && !has_execution_postcondition(
            &agent_state.tool_execution_log,
            CLOCK_TIMESTAMP_POSTCONDITION,
        )
    {
        push_unique_missing(
            &mut missing,
            postcondition_marker(CLOCK_TIMESTAMP_POSTCONDITION),
        );
    }
    if requires_timer_notification_contract(agent_state) {
        if !has_execution_postcondition(
            &agent_state.tool_execution_log,
            TIMER_SLEEP_BACKEND_POSTCONDITION,
        ) {
            push_unique_missing(
                &mut missing,
                postcondition_marker(TIMER_SLEEP_BACKEND_POSTCONDITION),
            );
        }
        if has_execution_postcondition(
            &agent_state.tool_execution_log,
            TIMER_SLEEP_BACKEND_POSTCONDITION,
        ) && !has_execution_postcondition(
            &agent_state.tool_execution_log,
            TIMER_NOTIFICATION_PATH_POSTCONDITION,
        ) {
            push_unique_missing(
                &mut missing,
                postcondition_marker(TIMER_NOTIFICATION_PATH_POSTCONDITION),
            );
        }
    }

    missing
}

pub fn missing_execution_contract_markers(agent_state: &AgentState) -> Vec<String> {
    let default_matrix = IntentRoutingPolicy::default().matrix;
    let (required_receipts, required_postconditions) =
        resolved_contract_requirements(agent_state, Some(&default_matrix));
    collect_missing_contract_markers(agent_state, &required_receipts, &required_postconditions)
}

pub fn missing_execution_contract_markers_with_rules(
    agent_state: &AgentState,
    rules: &ActionRules,
) -> Vec<String> {
    let (required_receipts, required_postconditions) = resolved_contract_requirements(
        agent_state,
        Some(&rules.ontology_policy.intent_routing.matrix),
    );
    collect_missing_contract_markers(agent_state, &required_receipts, &required_postconditions)
}
