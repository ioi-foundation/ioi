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
    let tool_allowed = is_tool_allowed_for_resolution(
        agent_state.resolved_intent.as_ref(),
        current_tool_name,
    )
        || (crate::agentic::runtime::workspace_change::workspace_change_lifecycle_goal_requested(
            &agent_state.goal,
        )
            && crate::agentic::runtime::workspace_change::workspace_change_lifecycle_control_tool(
                current_tool_name,
            ));
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

    if let Some(contract_error) = typed_route_shell_command_contract_violation(agent_state, tool) {
        *policy_decision = "denied".to_string();
        *success = false;
        *error_msg = Some(contract_error.clone());
        *history_entry = Some(contract_error.clone());
        *action_output = Some(contract_error.clone());
        verification_checks.push("runtime_route_command_contract_blocked=true".to_string());
        verification_checks.push("execution_contract_gate_blocked=true".to_string());
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "provider_selection",
            "runtime_route_command_contract",
            false,
            "shell_command_mismatch",
            None,
            route_label.map(str::to_string),
            synthesized_payload_hash.clone(),
        );
        if !req_hash_hex.is_empty() {
            agent_state.tool_execution_log.insert(
                req_hash_hex.to_string(),
                ToolCallStatus::Failed(
                    "ERROR_CLASS=ExecutionContractViolation runtime_route_command_contract"
                        .to_string(),
                ),
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

    if retained_helper_goal_requires_complete_command(&agent_state.goal) {
        if let Some(command) = bare_retained_interpreter_command(tool) {
            let contract_error = format!(
                "ERROR_CLASS=ActionContractViolation Retained shell helper must start a complete observable command, not bare interpreter '{}'. Use `shell__start` with command arguments that implement the helper, then use `shell__status`, `shell__input`, `shell__terminate`, and `shell__reset`.",
                command
            );
            *policy_decision = "denied".to_string();
            *success = false;
            *error_msg = Some(contract_error.clone());
            *history_entry = Some(contract_error.clone());
            *action_output = Some(contract_error.clone());
            verification_checks.push("retained_helper_bare_interpreter_blocked=true".to_string());
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "provider_selection",
                "retained_helper_complete_command",
                false,
                &contract_error,
                None,
                route_label.map(str::to_string),
                synthesized_payload_hash.clone(),
            );
            if !req_hash_hex.is_empty() {
                agent_state.tool_execution_log.insert(
                    req_hash_hex.to_string(),
                    ToolCallStatus::Failed("retained_helper_bare_interpreter".to_string()),
                );
            }
            return false;
        }
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

pub(super) fn typed_route_shell_command_contract_violation(
    agent_state: &AgentState,
    tool: &AgentTool,
) -> Option<String> {
    let frame = agent_state.runtime_route_frame.as_ref()?;
    if frame.direct_answer_allowed
        || !frame.output_intent.eq_ignore_ascii_case("tool_execution")
        || !frame.intent_id.eq_ignore_ascii_case("command.exec")
    {
        return None;
    }
    let command_plan = frame.runtime_action.as_ref()?.command_plan.as_ref()?;
    if command_plan.argv.is_empty() {
        return None;
    }
    if typed_route_shell_command_matches_plan(&command_plan.argv, tool) {
        return None;
    }
    Some(
        "ERROR_CLASS=ExecutionContractViolation Shell command did not match the typed runtime command target. Report the result of the requested command instead of substituting another command."
            .to_string(),
    )
}

fn typed_route_shell_command_matches_plan(expected_argv: &[String], tool: &AgentTool) -> bool {
    let Some((command, args)) = shell_command_argv_for_tool(tool) else {
        return true;
    };
    let Some((expected_command, expected_args)) = expected_argv.split_first() else {
        return true;
    };
    command.trim() == expected_command.trim()
        && args.len() == expected_args.len()
        && args
            .iter()
            .zip(expected_args.iter())
            .all(|(actual, expected)| actual.trim() == expected.trim())
}

fn shell_command_argv_for_tool(tool: &AgentTool) -> Option<(&str, &[String])> {
    match tool {
        AgentTool::SysExec { command, args, .. }
        | AgentTool::SysExecSession { command, args, .. } => Some((command.as_str(), args)),
        _ => None,
    }
}

fn retained_helper_goal_requires_complete_command(goal: &str) -> bool {
    let normalized = goal.to_ascii_lowercase();
    let retained_surface = [
        "retained",
        "persistent",
        "long-running",
        "long running",
        "background",
    ]
    .iter()
    .any(|cue| normalized.contains(cue));
    let helper_surface = ["helper", "process", "command", "session", "shell"]
        .iter()
        .any(|cue| normalized.contains(cue));
    let control_surface = [
        "stdin",
        "input",
        "status",
        "terminate",
        "reset",
        "shell__input",
        "shell__status",
        "shell__terminate",
        "shell__reset",
    ]
    .iter()
    .any(|cue| normalized.contains(cue));
    let explicitly_interactive_repl = [
        "interactive repl",
        "node repl",
        "python repl",
        "repl session",
    ]
    .iter()
    .any(|cue| normalized.contains(cue));

    retained_surface && helper_surface && control_surface && !explicitly_interactive_repl
}

fn bare_retained_interpreter_command(tool: &AgentTool) -> Option<String> {
    let AgentTool::SysExecSession {
        command,
        args,
        stdin,
        ..
    } = tool
    else {
        return None;
    };
    if !args.is_empty()
        || stdin
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
    {
        return None;
    }

    let binary = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command.as_str())
        .trim()
        .to_ascii_lowercase();
    let bare_interpreters = [
        "node", "python", "python3", "python2", "ipython", "ruby", "php", "perl", "bash", "sh",
        "zsh", "fish",
    ];
    bare_interpreters
        .iter()
        .any(|candidate| binary == *candidate)
        .then(|| command.trim().to_string())
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
        "{} install_resolution_stage={} install_display_name={} install_manager={} install_source_kind={}",
        blocker, summary.stage, display_name, manager, source_kind
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::execution::system::software_install_plan_ref_for_request;
    use crate::agentic::runtime::types::{AgentMode, AgentStatus, ExecutionTier};
    use ioi_types::app::agentic::{
        CommandExecutionPlanRef, RuntimeActionFrame, RuntimeRouteFrame, SoftwareInstallRequestFrame,
    };

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

    fn software_install_resolve_tool(
        target_text: &str,
        manager_preference: Option<&str>,
    ) -> AgentTool {
        AgentTool::SoftwareInstallResolve {
            request: SoftwareInstallRequestFrame {
                target_text: target_text.to_string(),
                target_kind: None,
                manager_preference: manager_preference.map(str::to_string),
                launch_after_install: None,
                provenance: Some("test".to_string()),
            },
        }
    }

    fn sys_exec_tool(command: &str, args: Vec<&str>) -> AgentTool {
        AgentTool::SysExec {
            command: command.to_string(),
            args: args.into_iter().map(str::to_string).collect(),
            stdin: None,
            wait_ms_before_async: Some(50),
            detach: false,
        }
    }

    fn sys_exec_session_tool(command: &str, args: Vec<&str>) -> AgentTool {
        AgentTool::SysExecSession {
            command: command.to_string(),
            args: args.into_iter().map(str::to_string).collect(),
            stdin: None,
            wait_ms_before_async: Some(50),
        }
    }

    fn typed_command_route_frame(argv: Vec<&str>) -> RuntimeRouteFrame {
        RuntimeRouteFrame {
            intent_id: "command.exec".to_string(),
            route_family: "command_execution".to_string(),
            output_intent: "tool_execution".to_string(),
            direct_answer_allowed: false,
            target: "run the requested command".to_string(),
            target_kind: Some("shell_command".to_string()),
            host_mutation: false,
            required_capabilities: vec!["command.exec".to_string()],
            typed_evidence: vec![],
            typed_required_capabilities: vec![],
            host_mutation_scope: None,
            runtime_action: Some(RuntimeActionFrame {
                intent_class: "local_runtime_action".to_string(),
                action_family: "shell".to_string(),
                target_text: "run the requested command".to_string(),
                target_kind: "shell_command".to_string(),
                host_mutation: false,
                required_capabilities: vec![],
                browser_plan: None,
                command_plan: Some(CommandExecutionPlanRef {
                    plan_ref: "command.exec:test".to_string(),
                    argv: argv.into_iter().map(str::to_string).collect(),
                    shell_policy: "bounded".to_string(),
                    cwd: Some(".".to_string()),
                    env: Vec::new(),
                    approval_scope: None,
                    expected_receipt: Some("command_receipt".to_string()),
                }),
                file_plan: None,
                provenance: Some("test".to_string()),
            }),
            install_request: None,
            provenance: Some("test".to_string()),
        }
    }

    fn route_frame_agent_state(frame: RuntimeRouteFrame) -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: "Run `sleep 900` through the governed shell tool.".to_string(),
            runtime_route_frame: Some(frame),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 1,
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
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: Default::default(),
            execution_ledger: Default::default(),
            visual_som_map: None,
            visual_semantic_map: None,
            work_graph_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: Default::default(),
            active_lens: None,
        }
    }

    #[test]
    fn retained_helper_contract_detects_bare_interpreter() {
        let goal = "Start a disposable retained Node.js helper that waits for stdin, check status, send input, terminate, and reset retained shell state.";
        assert!(retained_helper_goal_requires_complete_command(goal));

        let bare_node = sys_exec_session_tool("node", vec![]);
        assert_eq!(
            bare_retained_interpreter_command(&bare_node).as_deref(),
            Some("node")
        );

        let complete_node = sys_exec_session_tool(
            "node",
            vec![
                "-e",
                "process.stdin.resume(); process.stdin.on('data', d => console.log(`status:${d.toString().trim()}`));",
            ],
        );
        assert!(bare_retained_interpreter_command(&complete_node).is_none());
    }

    #[test]
    fn retained_helper_contract_allows_explicit_repl_goals() {
        let goal = "Start an interactive REPL session in a retained shell.";
        assert!(!retained_helper_goal_requires_complete_command(goal));
    }

    #[test]
    fn unresolved_auto_install_blocks_before_approval() {
        let tool = software_install_resolve_tool("snorflepaint", Some("auto"));
        let blocker = install_resolution_preapproval_blocker(&tool)
            .expect("unknown auto target should block before approval");

        assert!(blocker.contains("InstallerResolutionRequired"));
        assert!(blocker.contains("install_resolution_stage=unresolved"));
        assert!(blocker.contains("install_source_kind=unresolved"));
    }

    #[test]
    fn unsupported_manual_install_blocks_before_approval() {
        let tool = software_install_resolve_tool("snorflepaint", Some("auto"));
        let blocker = install_resolution_preapproval_blocker(&tool)
            .expect("manual installer target without executable plan should block");

        assert!(blocker.contains("InstallerResolutionRequired"));
        assert!(blocker.contains("install_resolution_stage=unresolved"));
        assert!(blocker.contains("install_source_kind=unresolved"));
    }

    #[test]
    fn resolved_package_install_can_reach_policy_approval() {
        let tool = software_install_execute_plan_tool("generic tool", Some("apt-get"));

        assert!(install_resolution_preapproval_blocker(&tool).is_none());
    }

    #[test]
    fn typed_route_shell_command_contract_allows_exact_target_command() {
        let state = route_frame_agent_state(typed_command_route_frame(vec!["sleep", "900"]));
        let tool = sys_exec_tool("sleep", vec!["900"]);

        assert!(typed_route_shell_command_contract_violation(&state, &tool).is_none());
    }

    #[test]
    fn typed_route_shell_command_contract_blocks_substituted_command() {
        let state = route_frame_agent_state(typed_command_route_frame(vec!["sleep", "900"]));
        let tool = sys_exec_tool(
            "systemd-run",
            vec!["--user", "notify-send", "Timer Complete"],
        );

        let violation = typed_route_shell_command_contract_violation(&state, &tool)
            .expect("substituted shell command should be blocked");
        assert!(violation.contains("ERROR_CLASS=ExecutionContractViolation"));
        assert!(!violation.contains("systemd-run"));
        assert!(!violation.contains("command.exec:test"));
    }
}
