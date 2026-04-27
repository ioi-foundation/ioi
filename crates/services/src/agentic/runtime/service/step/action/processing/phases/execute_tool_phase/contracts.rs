use super::events::{
    emit_execution_contract_receipt_event, resolved_intent_id, synthesized_payload_hash_for_tool,
};
use super::*;

pub(super) struct ContractBootstrap {
    pub command_scope: bool,
    pub resolved_intent_id: String,
    pub synthesized_payload_hash: Option<String>,
    pub route_label: Option<String>,
}

pub(super) fn bootstrap_contract(
    service: &RuntimeAgentService,
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
    let route_label = capability_route_label(tool, current_tool_name);

    if route_label.is_some()
        && !has_execution_evidence(&agent_state.tool_execution_log, "host_discovery")
    {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let host_receipt = runtime_host_environment_evidence(timestamp_ms);
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
            record_execution_evidence_with_value(
                &mut agent_state.tool_execution_log,
                "host_discovery",
                host_receipt.observed_value.clone(),
            );
            verification_checks.push(execution_evidence_key("host_discovery"));
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

    if let Some(route_label) = route_label.as_deref() {
        verification_checks.push(format!("capability_route_selected={}", route_label));
        record_provider_selection_evidence(
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
        let provider_selection_commit = execution_evidence_value(
            &agent_state.tool_execution_log,
            PROVIDER_SELECTION_COMMIT_EVIDENCE,
        )
        .map(str::to_string);
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            &resolved_intent_id,
            "provider_selection",
            PROVIDER_SELECTION_COMMIT_EVIDENCE,
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

    if command_scope && is_command_execution_provider_tool(tool) {
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
    agent_state: &mut AgentState,
    tool: &AgentTool,
    _command_scope: bool,
    current_step_index: u32,
    action_fingerprint: &str,
    verification_checks: &mut Vec<String>,
) -> (
    bool,
    Option<crate::agentic::runtime::types::CommandExecution>,
) {
    let is_command_tool = matches!(
        tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    );
    let action_fingerprint_step = if action_fingerprint.is_empty() {
        None
    } else {
        let step =
            action_fingerprint_execution_step(&agent_state.tool_execution_log, action_fingerprint);
        if step.is_none()
            && drop_legacy_action_fingerprint_receipt(
                &mut agent_state.tool_execution_log,
                action_fingerprint,
            )
        {
            verification_checks
                .push("duplicate_action_fingerprint_legacy_removed=true".to_string());
        }
        step
    };
    let duplicate_marker_seen = action_fingerprint_step.is_some();
    let matching_command_history_entry = if duplicate_marker_seen {
        if is_command_tool {
            find_matching_command_history_entry(tool, &agent_state.command_history).cloned()
        } else {
            None
        }
    } else {
        None
    };
    if duplicate_marker_seen && is_command_tool && matching_command_history_entry.is_none() {
        verification_checks
            .push("duplicate_action_fingerprint_stale_or_cross_turn=true".to_string());
    }
    let duplicate_safe_repeat_tool = is_duplicate_safe_repeat_tool(tool);
    let duplicate_non_command_immediate_replay =
        if duplicate_marker_seen && !is_command_tool && !duplicate_safe_repeat_tool {
            action_fingerprint_step
                .map(|last_step_index| current_step_index == last_step_index.saturating_add(1))
                .unwrap_or(false)
        } else {
            false
        };
    if duplicate_marker_seen
        && !is_command_tool
        && !duplicate_safe_repeat_tool
        && !duplicate_non_command_immediate_replay
    {
        verification_checks.push(
            "duplicate_action_fingerprint_non_command_stale_or_non_adjacent=true".to_string(),
        );
    }
    (
        if is_command_tool {
            duplicate_marker_seen && matching_command_history_entry.is_some()
        } else {
            duplicate_non_command_immediate_replay
        },
        matching_command_history_entry,
    )
}

fn is_duplicate_safe_repeat_tool(tool: &AgentTool) -> bool {
    match tool {
        AgentTool::BrowserWait { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserHover { .. }
        | AgentTool::AgentAwait { .. } => true,
        AgentTool::BrowserKey { key, .. } => is_repeatable_browser_motion_key(key),
        _ => false,
    }
}

fn is_repeatable_browser_motion_key(key: &str) -> bool {
    matches!(
        key,
        "ArrowUp"
            | "ArrowDown"
            | "ArrowLeft"
            | "ArrowRight"
            | "PageUp"
            | "PageDown"
            | "Home"
            | "End"
            | "Tab"
    )
}

#[cfg(test)]
#[path = "contracts/tests.rs"]
mod tests;
