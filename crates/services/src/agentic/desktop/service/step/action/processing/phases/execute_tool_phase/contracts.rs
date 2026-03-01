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

    if route_label.is_some()
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
    Option<crate::agentic::desktop::types::CommandExecution>,
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
    let duplicate_non_command_immediate_replay = if duplicate_marker_seen && !is_command_tool {
        action_fingerprint_step
            .map(|last_step_index| current_step_index == last_step_index.saturating_add(1))
            .unwrap_or(false)
    } else {
        false
    };
    if duplicate_marker_seen && !is_command_tool && !duplicate_non_command_immediate_replay {
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

#[cfg(test)]
mod tests {
    use super::duplicate_execution_state;
    use crate::agentic::desktop::service::step::action::mark_action_fingerprint_executed_at_step;
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, ExecutionTier, ToolCallStatus,
    };
    use ioi_types::app::agentic::AgentTool;
    use std::collections::BTreeMap;

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: "test".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: Default::default(),
            active_lens: None,
        }
    }

    #[test]
    fn duplicate_non_command_replay_detected_only_on_adjacent_step() {
        let mut state = test_agent_state();
        mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
        let tool = AgentTool::FsList {
            path: ".".to_string(),
        };
        let mut checks = Vec::new();
        let (is_duplicate, history) =
            duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
        assert!(is_duplicate);
        assert!(history.is_none());
        assert!(!checks.iter().any(|c| {
            c == "duplicate_action_fingerprint_non_command_stale_or_non_adjacent=true"
        }));
    }

    #[test]
    fn duplicate_non_command_non_adjacent_step_is_not_forced_duplicate() {
        let mut state = test_agent_state();
        mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
        let tool = AgentTool::FsList {
            path: ".".to_string(),
        };
        let mut checks = Vec::new();
        let (is_duplicate, history) =
            duplicate_execution_state(&mut state, &tool, false, 7, "fp", &mut checks);
        assert!(!is_duplicate);
        assert!(history.is_none());
        assert!(checks.iter().any(|c| {
            c == "duplicate_action_fingerprint_non_command_stale_or_non_adjacent=true"
        }));
    }

    #[test]
    fn duplicate_non_command_cooldown_step_blocks_alternating_replay_loop() {
        let mut state = test_agent_state();
        let tool = AgentTool::FsList {
            path: ".".to_string(),
        };
        let mut checks = Vec::new();

        mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");

        let (duplicate_at_step_4, _) =
            duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
        assert!(duplicate_at_step_4);

        // Duplicate-skip branch advances the fingerprint step to the current step.
        mark_action_fingerprint_executed_at_step(
            &mut state.tool_execution_log,
            "fp",
            4,
            "duplicate_skip",
        );

        let (duplicate_at_step_5, _) =
            duplicate_execution_state(&mut state, &tool, false, 5, "fp", &mut checks);
        assert!(duplicate_at_step_5);
    }

    #[test]
    fn legacy_action_fingerprint_receipt_is_removed_and_not_used_for_dedupe() {
        let mut state = test_agent_state();
        state.tool_execution_log.insert(
            "action_fingerprint::legacy".to_string(),
            ToolCallStatus::Executed("success".to_string()),
        );
        let tool = AgentTool::FsList {
            path: ".".to_string(),
        };
        let mut checks = Vec::new();
        let (is_duplicate, history) =
            duplicate_execution_state(&mut state, &tool, false, 8, "legacy", &mut checks);
        assert!(!is_duplicate);
        assert!(history.is_none());
        assert!(checks
            .iter()
            .any(|c| c == "duplicate_action_fingerprint_legacy_removed=true"));
        assert!(!state
            .tool_execution_log
            .contains_key("action_fingerprint::legacy"));
    }
}
