use super::events::{
    emit_execution_contract_receipt_event, resolved_intent_id, synthesized_payload_hash_for_tool,
};
use super::*;

pub(super) struct ContractBootstrap {
    pub command_scope: bool,
    pub resolved_intent_id: String,
    pub synthesized_payload_hash: Option<String>,
    pub route_label: Option<&'static str>,
}

pub(super) fn bootstrap_contract(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    tool: &AgentTool,
    current_tool_name: &str,
    session_id: [u8; 32],
    step_index: u32,
    verification_checks: &mut Vec<String>,
) -> ContractBootstrap {
    let command_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
        .unwrap_or(false);
    let resolved_intent_id = resolved_intent_id(agent_state);
    let synthesized_payload_hash = synthesized_payload_hash_for_tool(tool);
    let route_label = capability_route_label(tool);

    if command_scope
        && route_label.is_some()
        && !has_execution_receipt(&agent_state.tool_execution_log, "host_discovery")
    {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let host_receipt = runtime_host_environment_receipt(timestamp_ms);
        let desktop_dir = host_receipt
            .desktop_directory
            .clone()
            .unwrap_or_else(|| "unavailable".to_string());
        let evidence_material = format!(
            "observed_value={};probe_source={};timestamp_ms={};satisfied={};desktop_dir={}",
            host_receipt.observed_value.as_str(),
            host_receipt.probe_source.as_str(),
            host_receipt.timestamp_ms,
            host_receipt.satisfied,
            desktop_dir
        );
        verification_checks.push("capability_execution_phase=discovery".to_string());
        verification_checks.push(format!(
            "host_home_dir={}",
            host_receipt.observed_value.as_str()
        ));
        verification_checks.push(format!("host_desktop_dir={}", desktop_dir));
        verification_checks.push(format!(
            "host_discovery_probe_source={}",
            host_receipt.probe_source.as_str()
        ));
        verification_checks.push(format!(
            "host_discovery_timestamp_ms={}",
            host_receipt.timestamp_ms
        ));
        verification_checks.push(format!(
            "host_discovery_satisfied={}",
            host_receipt.satisfied
        ));
        if host_receipt.satisfied {
            mark_execution_receipt_with_value(
                &mut agent_state.tool_execution_log,
                "host_discovery",
                host_receipt.observed_value.clone(),
            );
            verification_checks.push(receipt_marker("host_discovery"));
        }
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            &resolved_intent_id,
            "discovery",
            "host_discovery",
            host_receipt.satisfied,
            &evidence_material,
            None,
            None,
            None,
        );
    }

    if let Some(route_label) = route_label {
        verification_checks.push(format!("capability_route_selected={}", route_label));
        if command_scope {
            record_provider_selection_receipts(
                &mut agent_state.tool_execution_log,
                verification_checks,
                current_tool_name,
                route_label,
            );
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                &resolved_intent_id,
                "provider_selection",
                "provider_selection",
                true,
                &format!("route_label={}", route_label),
                None,
                Some(route_label.to_string()),
                synthesized_payload_hash.clone(),
            );
            let provider_selection_commit = execution_receipt_value(
                &agent_state.tool_execution_log,
                PROVIDER_SELECTION_COMMIT_RECEIPT,
            )
            .map(str::to_string);
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                &resolved_intent_id,
                "provider_selection",
                PROVIDER_SELECTION_COMMIT_RECEIPT,
                provider_selection_commit
                    .as_deref()
                    .map(|value| value.starts_with("sha256:"))
                    .unwrap_or(false),
                provider_selection_commit
                    .as_deref()
                    .unwrap_or("provider_selection_commit=missing"),
                None,
                Some(route_label.to_string()),
                synthesized_payload_hash.clone(),
            );
        }
    }

    if command_scope
        && matches!(
            tool,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
    {
        verification_checks.push("capability_execution_phase=execution".to_string());
    }

    ContractBootstrap {
        command_scope,
        resolved_intent_id,
        synthesized_payload_hash,
        route_label,
    }
}

pub(super) fn duplicate_execution_state(
    agent_state: &AgentState,
    tool: &AgentTool,
    command_scope: bool,
    action_fingerprint: &str,
    verification_checks: &mut Vec<String>,
) -> (
    bool,
    Option<crate::agentic::desktop::types::CommandExecution>,
) {
    let duplicate_marker_seen = command_scope
        && matches!(
            tool,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
        && !action_fingerprint.is_empty()
        && is_action_fingerprint_executed(&agent_state.tool_execution_log, action_fingerprint);
    let matching_command_history_entry = if duplicate_marker_seen {
        find_matching_command_history_entry(tool, &agent_state.command_history).cloned()
    } else {
        None
    };
    if duplicate_marker_seen && matching_command_history_entry.is_none() {
        verification_checks
            .push("duplicate_action_fingerprint_stale_or_cross_turn=true".to_string());
    }
    (
        duplicate_marker_seen && matching_command_history_entry.is_some(),
        matching_command_history_entry,
    )
}
