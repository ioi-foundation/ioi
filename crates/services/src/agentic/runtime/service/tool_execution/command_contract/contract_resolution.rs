use crate::agentic::runtime::service::decision_loop::intent_resolver::{
    tool_has_capability, tool_provider_route_label,
};

fn uses_native_integration_route(tool_name: &str, target: &ActionTarget) -> bool {
    matches!(
        target,
        ActionTarget::WindowFocus
            | ActionTarget::ClipboardWrite
            | ActionTarget::ClipboardRead
            | ActionTarget::BrowserInteract
            | ActionTarget::BrowserInspect
            | ActionTarget::GuiClick
            | ActionTarget::GuiType
            | ActionTarget::GuiScroll
            | ActionTarget::GuiInspect
            | ActionTarget::FsRead
            | ActionTarget::FsWrite
    ) || [
        "agent.lifecycle",
        "app.launch",
        "automation.monitor.install",
        "clipboard.read",
        "clipboard.write",
        "conversation.reply",
        "delegation.manage",
        "filesystem.metadata",
        "filesystem.read",
        "filesystem.write",
        "memory.access",
    ]
    .into_iter()
    .any(|capability| tool_has_capability(tool_name, capability))
}

pub fn capability_route_label(tool: &AgentTool, tool_name: &str) -> Option<String> {
    match tool {
        AgentTool::SoftwareInstallExecutePlan { .. } => Some("enablement_request".to_string()),
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. } => {
            Some("script_backend".to_string())
        }
        _ => {
            if let Some(route_label) = tool_provider_route_label(tool_name) {
                return Some(route_label.to_string());
            }
            if uses_native_integration_route(tool_name, &tool.target()) {
                return Some("native_integration".to_string());
            }
            None
        }
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

pub fn is_completion_contract_error(error: Option<&str>) -> bool {
    matches!(
        extract_error_class_token(error),
        Some("ExecutionContractViolation")
    )
}

pub fn execution_contract_violation_error(missing_keys: &str) -> String {
    let mut missing_evidence = Vec::<String>::new();
    let mut missing_success_conditions = Vec::<String>::new();
    for token in missing_keys
        .split(',')
        .map(|token| token.trim())
        .filter(|token| !token.is_empty())
    {
        if let Some(rest) = token.strip_prefix("evidence::") {
            missing_evidence.push(rest.trim_end_matches("=true").to_string());
        } else if let Some(rest) = token.strip_prefix("success_condition::") {
            missing_success_conditions.push(rest.trim_end_matches("=true").to_string());
        }
    }

    let (detail_class, failed_stage) = if missing_evidence
        .iter()
        .any(|receipt| receipt == "host_discovery")
    {
        ("DiscoveryMissing", "discovery")
    } else if missing_evidence.iter().any(|receipt| receipt == "grounding") {
        ("GroundingMissing", "grounding")
    } else if missing_evidence
        .iter()
        .any(|receipt| receipt == "provider_selection" || receipt == "provider_selection_commit")
    {
        ("SynthesisFailed", "provider_selection")
    } else if missing_evidence
        .iter()
        .any(|receipt| receipt == "verification" || receipt == "verification_commit")
    {
        ("VerificationMissing", "verification")
    } else if !missing_success_conditions.is_empty() {
        ("PostconditionFailed", "completion_gate")
    } else {
        ("ExecutionContractViolation", "completion_gate")
    };

    let missing_evidence_str = if missing_evidence.is_empty() {
        "none".to_string()
    } else {
        missing_evidence.join("|")
    };
    let missing_success_conditions_str = if missing_success_conditions.is_empty() {
        "none".to_string()
    } else {
        missing_success_conditions.join("|")
    };

    format!(
        "ERROR_CLASS=ExecutionContractViolation Execution contract unmet. failed_stage={} detail_class={} missing_evidence={} missing_success_conditions={} missing_keys={}",
        failed_stage, detail_class, missing_evidence_str, missing_success_conditions_str, missing_keys
    )
}

pub fn requires_timer_notification_contract(agent_state: &AgentState) -> bool {
    has_execution_evidence(
        &agent_state.tool_execution_log,
        TIMER_NOTIFICATION_CONTRACT_REQUIRED_EVIDENCE,
    ) || latest_timer_backend_history_entry(agent_state).is_some()
}

fn requires_typed_timer_notification_contract(agent_state: &AgentState) -> bool {
    agent_state
        .execution_ledger
        .has_evidence(TIMER_NOTIFICATION_CONTRACT_REQUIRED_EVIDENCE)
        || latest_timer_backend_history_entry(agent_state).is_some()
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
    record_execution_evidence(
        tool_execution_log,
        TIMER_NOTIFICATION_CONTRACT_REQUIRED_EVIDENCE,
    );
    verification_checks.push(execution_evidence_key(TIMER_NOTIFICATION_CONTRACT_REQUIRED_EVIDENCE));
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

fn required_completion_evidence_from_catalog(
    intent_id: &str,
    intent_catalog: &[IntentCatalogEntry],
) -> Option<(Vec<String>, Vec<String>)> {
    let entry = intent_catalog
        .iter()
        .find(|entry| entry.intent_id.trim() == intent_id.trim())?;
    Some((
        canonical_contract_markers(&entry.required_evidence),
        canonical_contract_markers(&entry.success_conditions),
    ))
}

fn resolved_contract_requirements(
    agent_state: &AgentState,
    intent_catalog: Option<&[IntentCatalogEntry]>,
) -> (Vec<String>, Vec<String>) {
    let command_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
        .unwrap_or(false);
    let resolved_contract = agent_state.resolved_intent.as_ref().and_then(|resolved| {
        let evidence = canonical_contract_markers(&resolved.required_evidence);
        let success_conditions = canonical_contract_markers(&resolved.success_conditions);
        if evidence.is_empty() && success_conditions.is_empty() {
            None
        } else {
            Some((evidence, success_conditions))
        }
    });
    let resolved_from_catalog = resolved_contract.or_else(|| {
        agent_state.resolved_intent.as_ref().and_then(|resolved| {
            intent_catalog.and_then(|entries| required_completion_evidence_from_catalog(&resolved.intent_id, entries))
        })
    });

    let mut required_evidence = resolved_from_catalog
        .as_ref()
        .map(|(evidence, _)| evidence.clone())
        .unwrap_or_default();
    let mut success_conditions = resolved_from_catalog
        .map(|(_, success_conditions)| success_conditions)
        .unwrap_or_default();

    if required_evidence.is_empty() && success_conditions.is_empty() && command_scope {
        append_unique_marker(&mut required_evidence, "host_discovery");
        for receipt in COMMAND_SCOPE_REQUIRED_EVIDENCE {
            append_unique_marker(&mut required_evidence, receipt);
        }
        for postcondition in COMMAND_SCOPE_SUCCESS_CONDITIONS {
            append_unique_marker(&mut success_conditions, postcondition);
        }
    }

    for rrsa_receipt in rrsa_required_receipts(agent_state) {
        append_unique_marker(&mut required_evidence, &rrsa_receipt);
    }
    if agent_state.pending_search_completion.is_some() {
        append_unique_marker(&mut required_evidence, WEB_PIPELINE_TERMINAL_EVIDENCE);
    }

    (required_evidence, success_conditions)
}

fn collect_missing_typed_contract_evidence(
    agent_state: &AgentState,
    required_evidence: &[String],
    success_conditions: &[String],
) -> Vec<String> {
    let mut missing = Vec::<String>::new();
    for receipt in required_evidence {
        let evidence_value = agent_state
            .execution_ledger
            .evidence_value(receipt)
            .unwrap_or_default()
            .trim()
            .to_string();
        if evidence_value.is_empty() {
            push_unique_missing(&mut missing, execution_evidence_key(receipt));
            continue;
        }
        if receipt_requires_commit_hash(receipt) && !evidence_value.starts_with("sha256:") {
            push_unique_missing(&mut missing, execution_evidence_key(receipt));
        }
    }

    for postcondition in success_conditions {
        if !agent_state
            .execution_ledger
            .has_success_condition(postcondition)
        {
            push_unique_missing(&mut missing, success_condition_key(postcondition));
        }
    }

    if is_system_clock_read_contract_intent(agent_state)
        && !agent_state
            .execution_ledger
            .has_success_condition(CLOCK_TIMESTAMP_SUCCESS_CONDITION)
    {
        push_unique_missing(
            &mut missing,
            success_condition_key(CLOCK_TIMESTAMP_SUCCESS_CONDITION),
        );
    }
    if requires_typed_timer_notification_contract(agent_state) {
        if !agent_state
            .execution_ledger
            .has_success_condition(TIMER_SLEEP_BACKEND_SUCCESS_CONDITION)
        {
            push_unique_missing(
                &mut missing,
                success_condition_key(TIMER_SLEEP_BACKEND_SUCCESS_CONDITION),
            );
        }
        if agent_state
            .execution_ledger
            .has_success_condition(TIMER_SLEEP_BACKEND_SUCCESS_CONDITION)
            && !agent_state
                .execution_ledger
                .has_success_condition(TIMER_NOTIFICATION_PATH_SUCCESS_CONDITION)
        {
            push_unique_missing(
                &mut missing,
                success_condition_key(TIMER_NOTIFICATION_PATH_SUCCESS_CONDITION),
            );
        }
    }

    let verification_required = required_evidence
        .iter()
        .any(|receipt| receipt == "verification" || receipt == VERIFICATION_COMMIT_EVIDENCE)
        || !success_conditions.is_empty();
    if verification_required
        && !agent_state
            .execution_ledger
            .has_verification_evidence()
    {
        push_unique_missing(&mut missing, execution_evidence_key("verification_evidence"));
    }

    missing
}

pub fn missing_completion_evidence_with_rules(
    agent_state: &AgentState,
    rules: &ActionRules,
) -> Vec<String> {
    let (mut required_evidence, success_conditions) = resolved_contract_requirements(
        agent_state,
        Some(&rules.ontology_policy.intent_routing.intent_catalog),
    );
    for rrsa_receipt in rrsa_required_receipts_from_ledger(agent_state) {
        append_unique_marker(&mut required_evidence, &rrsa_receipt);
    }
    collect_missing_typed_contract_evidence(
        agent_state,
        &required_evidence,
        &success_conditions,
    )
}

pub fn evaluate_completion_requirements(
    agent_state: &mut AgentState,
    intent_id: &str,
    verification_checks: &[String],
    rules: &ActionRules,
) -> Vec<String> {
    persist_step_evidence_to_ledger(agent_state, intent_id, verification_checks);
    let missing = missing_completion_evidence_with_rules(agent_state, rules);
    let ledger_intent_id = (!intent_id.trim().is_empty()).then(|| intent_id.to_string());
    agent_state
        .execution_ledger
        .record_completion_gate(ledger_intent_id, &missing);
    missing
}
