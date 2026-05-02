use super::events::emit_execution_contract_receipt_event;
use super::file_observation::enforce_file_write_observation;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn run_execution_prechecks(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    tool: &AgentTool,
    current_tool_name: &str,
    command_scope: bool,
    req_hash_hex: &str,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    route_label: Option<&str>,
    synthesized_payload_hash: Option<String>,
    verification_checks: &mut Vec<String>,
    policy_decision: &mut String,
    success: &mut bool,
    error_msg: &mut Option<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
) -> bool {
    let tool_allowed =
        is_tool_allowed_for_resolution(agent_state.resolved_intent.as_ref(), current_tool_name);
    if !tool_allowed {
        *policy_decision = "denied".to_string();
        *success = false;
        *error_msg = Some(format!(
            "ERROR_CLASS=PolicyBlocked Tool '{}' blocked by global intent scope.",
            current_tool_name
        ));
        if !req_hash_hex.is_empty() {
            agent_state.tool_execution_log.insert(
                req_hash_hex.to_string(),
                ToolCallStatus::Failed("intent_scope_block".to_string()),
            );
        }
        return false;
    }

    if let Some(already_satisfied) =
        crate::agentic::runtime::execution::system::install_already_satisfied_before_approval_for_tool(tool)
    {
        *policy_decision = "already_satisfied".to_string();
        *success = true;
        *history_entry = Some(already_satisfied.clone());
        *action_output = Some(already_satisfied.clone());
        verification_checks.push("install_already_satisfied_before_approval=true".to_string());
        if !req_hash_hex.is_empty() {
            agent_state.tool_execution_log.insert(
                req_hash_hex.to_string(),
                ToolCallStatus::Executed(
                    "install_already_satisfied_before_approval=true".to_string(),
                ),
            );
        }
        return false;
    }

    if let Some(blocker) = install_resolution_preapproval_blocker(tool) {
        *policy_decision = "resolver_blocked".to_string();
        *success = false;
        *error_msg = Some(blocker.clone());
        *history_entry = Some(blocker.clone());
        *action_output = Some(blocker.clone());
        verification_checks.push("software_install_blocked_before_approval=true".to_string());
        if !req_hash_hex.is_empty() {
            agent_state.tool_execution_log.insert(
                req_hash_hex.to_string(),
                ToolCallStatus::Failed("software_install_blocked_before_approval".to_string()),
            );
        }
        return false;
    }

    match enforce_file_write_observation(
        &agent_state.tool_execution_log,
        &agent_state.working_directory,
        tool,
        step_index,
    ) {
        Ok(Some(evidence)) => {
            verification_checks.push("workspace_file_observation_guard_passed=true".to_string());
            record_execution_evidence_with_value(
                &mut agent_state.tool_execution_log,
                "workspace_file_observation_guard",
                evidence.clone(),
            );
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "policy",
                "workspace_file_observation_guard",
                true,
                &evidence,
                None,
                route_label.map(str::to_string),
                synthesized_payload_hash.clone(),
            );
        }
        Ok(None) => {}
        Err(error) => {
            *policy_decision = "denied".to_string();
            *success = false;
            *error_msg = Some(error.clone());
            *history_entry = Some(error.clone());
            *action_output = Some(error.clone());
            verification_checks.push("workspace_file_observation_guard_blocked=true".to_string());
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "policy",
                "workspace_file_observation_guard",
                false,
                &error,
                None,
                route_label.map(str::to_string),
                synthesized_payload_hash.clone(),
            );
            if !req_hash_hex.is_empty() {
                agent_state.tool_execution_log.insert(
                    req_hash_hex.to_string(),
                    ToolCallStatus::Failed("workspace_file_observation_guard".to_string()),
                );
            }
            return false;
        }
    }

    if command_scope
        && is_system_clock_read_intent(agent_state.resolved_intent.as_ref())
        && matches!(
            tool,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
        && !sys_exec_satisfies_clock_read_contract(tool)
    {
        *policy_decision = "denied".to_string();
        *success = false;
        let missing = execution_evidence_key("provider_selection");
        let contract_error = execution_contract_violation_error(&missing);
        *error_msg = Some(contract_error.clone());
        *history_entry = Some(contract_error.clone());
        *action_output = Some(contract_error);
        verification_checks.push("clock_payload_contract_violation=true".to_string());
        verification_checks.push("execution_contract_gate_blocked=true".to_string());
        verification_checks.push(format!("execution_contract_missing_keys={}", missing));
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "provider_selection",
            "provider_selection",
            false,
            "clock_payload_lint_failed",
            None,
            route_label.map(str::to_string),
            synthesized_payload_hash,
        );
        if !req_hash_hex.is_empty() {
            agent_state.tool_execution_log.insert(
                req_hash_hex.to_string(),
                ToolCallStatus::Failed("clock_payload_contract_violation".to_string()),
            );
        }
        return false;
    }

    if command_scope
        && matches!(
            tool,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
    {
        if let Some(home_mismatch) = sys_exec_foreign_absolute_home_path(tool) {
            let timestamp_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let host_receipt = runtime_host_environment_evidence(timestamp_ms);
            let lint_error = format!(
                "ERROR_CLASS=SynthesisFailed stage=provider_selection cause=home_path_contract_lint_failed runtime_home_dir={} runtime_home_owner={} payload_home_dir={} payload_home_owner={}",
                home_mismatch.runtime_home_directory.as_str(),
                home_mismatch.runtime_home_owner.as_str(),
                home_mismatch.payload_home_directory.as_str(),
                home_mismatch.payload_home_owner.as_str()
            );
            let evidence_material = format!(
                "lint=home_path_owner_mismatch;observed_value={};probe_source={};timestamp_ms={};satisfied={};runtime_home_owner={};payload_home_owner={};payload_home_dir={}",
                host_receipt.observed_value.as_str(),
                host_receipt.probe_source.as_str(),
                host_receipt.timestamp_ms,
                host_receipt.satisfied,
                home_mismatch.runtime_home_owner.as_str(),
                home_mismatch.payload_home_owner.as_str(),
                home_mismatch.payload_home_directory.as_str()
            );

            *policy_decision = "denied".to_string();
            *success = false;
            *error_msg = Some(lint_error.clone());
            *history_entry = Some(lint_error.clone());
            *action_output = Some(lint_error.clone());

            verification_checks.push("cec_pre_execution_payload_lint_failed=true".to_string());
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks
                .push("execution_contract_failed_stage=provider_selection".to_string());
            verification_checks.push(
                "execution_contract_failure_cause=home_path_contract_lint_failed".to_string(),
            );
            verification_checks.push(format!(
                "host_home_dir={}",
                home_mismatch.runtime_home_directory.as_str()
            ));
            verification_checks.push(format!(
                "payload_home_dir={}",
                home_mismatch.payload_home_directory.as_str()
            ));
            verification_checks.push(format!(
                "host_home_owner={}",
                home_mismatch.runtime_home_owner.as_str()
            ));
            verification_checks.push(format!(
                "payload_home_owner={}",
                home_mismatch.payload_home_owner.as_str()
            ));
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
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "provider_selection",
                "provider_selection",
                false,
                &evidence_material,
                None,
                route_label.map(str::to_string),
                synthesized_payload_hash,
            );
            if !req_hash_hex.is_empty() {
                agent_state.tool_execution_log.insert(
                    req_hash_hex.to_string(),
                    ToolCallStatus::Failed("home_path_contract_lint_failed".to_string()),
                );
            }
            return false;
        }
    }

    true
}

fn install_resolution_preapproval_blocker(tool: &AgentTool) -> Option<String> {
    let summary = install_resolution_summary_for_tool(tool)?;
    if summary.stage.eq_ignore_ascii_case("resolved") {
        return None;
    }

    let display_name = summary.display_name.as_deref().unwrap_or("software");
    let manager = summary.manager.as_deref().unwrap_or("auto");
    let source_kind = summary.source_kind.as_deref().unwrap_or("unknown");
    let blocker = summary.blocker.unwrap_or_else(|| {
        "ERROR_CLASS=InstallerResolutionRequired Install target is not executable.".to_string()
    });
    Some(format!(
        "{} SOFTWARE_INSTALL stage='{}' display_name='{}' manager='{}' source_kind='{}'",
        blocker, summary.stage, display_name, manager, source_kind
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::execution::system::software_install_plan_ref_for_request;
    use ioi_types::app::agentic::SoftwareInstallRequestFrame;

    fn software_install_execute_plan_tool(
        target_text: &str,
        manager_preference: Option<&str>,
    ) -> AgentTool {
        let request = SoftwareInstallRequestFrame {
            target_text: target_text.to_string(),
            target_kind: None,
            manager_preference: manager_preference.map(str::to_string),
            launch_after_install: None,
            provenance: Some("test".to_string()),
        };
        AgentTool::SoftwareInstallExecutePlan {
            plan_ref: software_install_plan_ref_for_request(&request),
        }
    }

    #[test]
    fn unresolved_auto_install_blocks_before_approval() {
        let tool = software_install_execute_plan_tool("snorflepaint", Some("auto"));
        let blocker = install_resolution_preapproval_blocker(&tool)
            .expect("unknown auto target should block before approval");

        assert!(blocker.contains("InstallerResolutionRequired"));
        assert!(blocker.contains("stage='unresolved'"));
        assert!(blocker.contains("source_kind='unknown_target'"));
    }

    #[test]
    fn unsupported_manual_install_blocks_before_approval() {
        let tool = software_install_execute_plan_tool("snorflepaint", Some("auto"));
        let blocker = install_resolution_preapproval_blocker(&tool)
            .expect("manual installer target without executable plan should block");

        assert!(blocker.contains("InstallerResolutionRequired"));
        assert!(blocker.contains("stage='unresolved'"));
        assert!(blocker.contains("source_kind='unknown_target'"));
    }

    #[test]
    fn resolved_package_install_can_reach_policy_approval() {
        let tool = software_install_execute_plan_tool("generic tool", Some("apt-get"));

        assert!(install_resolution_preapproval_blocker(&tool).is_none());
    }
}
