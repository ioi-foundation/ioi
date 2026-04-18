use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::keys::get_state_key;
use crate::agentic::runtime::middleware::canonical_deterministic_tool_name;
use crate::agentic::runtime::service::lifecycle::load_worker_assignment;
use crate::agentic::runtime::service::step::action::execution_receipt_value;
use crate::agentic::runtime::service::step::anti_loop::{latest_failure_class, FailureClass};
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{AgentState, AgentStatus, WorkerAssignment};
use crate::agentic::runtime::utils::persist_agent_state;
use crate::agentic::runtime::worker_context::{
    collect_goal_literals, extract_worker_context_field, looks_like_command_literal,
    normalize_whitespace, split_parent_playbook_context,
};
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{AgentTool, LlmToolDefinition};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct WorkerExecutionResult {
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub attempts: u8,
}

pub(crate) fn worker_assignment_allows_tool_name(
    assignment: Option<&WorkerAssignment>,
    tool_name: &str,
) -> bool {
    if tool_name == "agent__escalate" {
        return true;
    }
    assignment
        .map(|assignment| {
            assignment.allowed_tools.is_empty()
                || assignment
                    .allowed_tools
                    .iter()
                    .any(|allowed| worker_assignment_tool_names_match(allowed, tool_name))
        })
        .unwrap_or(true)
}

fn worker_assignment_tool_names_match(allowed: &str, candidate: &str) -> bool {
    if allowed == candidate {
        return true;
    }

    match (
        canonical_deterministic_tool_name(allowed),
        canonical_deterministic_tool_name(candidate),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

pub(crate) fn worker_assignment_disallowed_tool_error(
    assignment: &WorkerAssignment,
    tool_name: &str,
) -> String {
    format!(
        "ERROR_CLASS=PolicyBlocked Worker playbook disallows tool '{}'. Allowed tools: {}.",
        tool_name,
        assignment.allowed_tools.join(", ")
    )
}

fn worker_assignment_tool_name_suppressed_by_recovery(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    last_failure_class: Option<FailureClass>,
    tool_name: &str,
) -> bool {
    if worker_assignment_should_suppress_redundant_change_directory(
        agent_state,
        Some(assignment),
        tool_name,
    ) {
        return true;
    }
    if worker_assignment_should_suppress_root_probes(Some(assignment), last_failure_class)
        && matches!(tool_name, "file__list" | "file__info")
    {
        return true;
    }
    if (worker_assignment_should_suppress_search_after_no_effect(
        Some(assignment),
        last_failure_class,
    ) || worker_assignment_has_likely_file_context(Some(assignment)))
        && tool_name == "file__search"
    {
        return true;
    }
    if worker_assignment_should_suppress_targeted_exec_until_workspace_edit(
        agent_state,
        Some(assignment),
        last_failure_class,
        tool_name,
    ) {
        return true;
    }
    worker_assignment_should_suppress_reads_after_no_effect(
        agent_state,
        Some(assignment),
        last_failure_class,
    ) && tool_name == "file__read"
}

fn worker_assignment_allows_tool_name_for_recovery(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
    tool_name: &str,
) -> bool {
    assignment
        .map(|assignment| {
            worker_assignment_allows_tool_name(Some(assignment), tool_name)
                && !worker_assignment_tool_name_suppressed_by_recovery(
                    agent_state,
                    assignment,
                    last_failure_class,
                    tool_name,
                )
        })
        .unwrap_or(true)
}

fn worker_assignment_allowed_tool_names_for_recovery(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    last_failure_class: Option<FailureClass>,
) -> Vec<String> {
    assignment
        .allowed_tools
        .iter()
        .filter(|tool_name| {
            worker_assignment_allows_tool_name_for_recovery(
                agent_state,
                Some(assignment),
                last_failure_class,
                tool_name,
            )
        })
        .cloned()
        .collect()
}

fn worker_assignment_recovery_disallowed_tool_error(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    last_failure_class: Option<FailureClass>,
    tool_name: &str,
) -> String {
    let allowed = worker_assignment_allowed_tool_names_for_recovery(
        agent_state,
        assignment,
        last_failure_class,
    );
    format!(
        "ERROR_CLASS=PolicyBlocked Worker recovery disallows tool '{}' after {}. Allowed tools now: {}.",
        tool_name,
        last_failure_class
            .map(FailureClass::as_str)
            .unwrap_or("current state"),
        allowed.join(", ")
    )
}

pub(crate) fn filter_tools_for_worker_assignment(
    tools: &[LlmToolDefinition],
    assignment: Option<&WorkerAssignment>,
) -> Vec<LlmToolDefinition> {
    let Some(assignment) = assignment else {
        return tools.to_vec();
    };
    if assignment.allowed_tools.is_empty() {
        return tools.to_vec();
    }

    tools
        .iter()
        .filter(|tool| worker_assignment_allows_tool_name(Some(assignment), &tool.name))
        .cloned()
        .collect()
}

fn normalize_existing_goal_path(candidate: &str) -> Option<PathBuf> {
    let trimmed = candidate
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ',' | ';' | ')'));
    if trimmed.is_empty() {
        return None;
    }

    let path = PathBuf::from(trimmed);
    let metadata = std::fs::metadata(&path).ok()?;
    if metadata.is_dir() {
        Some(path)
    } else {
        path.parent().map(Path::to_path_buf)
    }
}

fn goal_working_directory_matches_agent_state(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> bool {
    let current = agent_state.working_directory.trim();
    if current.is_empty() {
        return false;
    }

    collect_goal_literals(&assignment.goal)
        .into_iter()
        .filter_map(|literal| normalize_existing_goal_path(&literal))
        .any(|path| path == PathBuf::from(current))
}

fn first_goal_command_literal(goal: &str) -> Option<String> {
    let (_, inherited_context) = split_parent_playbook_context(goal);
    if let Some(command) = inherited_context
        .and_then(|text| {
            extract_worker_context_field(
                text,
                &[
                    "targeted_checks",
                    "targeted_check",
                    "verification_plan",
                    "verification",
                ],
            )
        })
        .and_then(|value| value.split(';').next().map(str::trim).map(str::to_string))
        .map(|value| normalize_whitespace(&value))
        .filter(|value| looks_like_command_literal(value))
    {
        return Some(command);
    }

    collect_goal_literals(goal)
        .into_iter()
        .map(|literal| normalize_whitespace(&literal))
        .find(|literal| looks_like_command_literal(literal))
}

fn is_patch_build_verify_assignment(assignment: Option<&WorkerAssignment>) -> bool {
    assignment
        .and_then(|assignment| assignment.workflow_id.as_deref())
        .map(str::trim)
        == Some("patch_build_verify")
}

fn worker_assignment_has_likely_file_context(assignment: Option<&WorkerAssignment>) -> bool {
    let Some(assignment) = assignment else {
        return false;
    };
    if !is_patch_build_verify_assignment(Some(assignment)) {
        return false;
    }

    let (_, inherited_context) = split_parent_playbook_context(&assignment.goal);
    let Some(value) =
        inherited_context.and_then(|text| extract_worker_context_field(text, &["likely_files"]))
    else {
        return false;
    };
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    !compact.is_empty() && !compact.to_ascii_lowercase().starts_with("repo root:")
}

fn worker_assignment_should_suppress_root_probes(
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
) -> bool {
    is_patch_build_verify_assignment(assignment)
        && (worker_assignment_has_likely_file_context(assignment)
            || matches!(last_failure_class, Some(FailureClass::NoEffectAfterAction)))
}

fn worker_assignment_should_suppress_search_after_no_effect(
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
) -> bool {
    is_patch_build_verify_assignment(assignment)
        && matches!(last_failure_class, Some(FailureClass::NoEffectAfterAction))
}

fn worker_assignment_should_suppress_reads_after_no_effect(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
) -> bool {
    is_patch_build_verify_assignment(assignment)
        && matches!(last_failure_class, Some(FailureClass::NoEffectAfterAction))
        && !patch_miss_refresh_read_ready(agent_state)
}

fn latest_workspace_patch_miss_step(agent_state: &AgentState) -> Option<u32> {
    execution_receipt_value(
        &agent_state.tool_execution_log,
        "workspace_patch_miss_observed",
    )
    .and_then(parse_receipt_step)
}

fn latest_workspace_read_step_any(agent_state: &AgentState) -> Option<u32> {
    execution_receipt_value(&agent_state.tool_execution_log, "workspace_read_observed")
        .and_then(parse_receipt_step)
}

fn patch_miss_refresh_read_ready(agent_state: &AgentState) -> bool {
    let Some(patch_miss_step) = latest_workspace_patch_miss_step(agent_state) else {
        return false;
    };

    latest_workspace_read_step_any(agent_state)
        .map(|read_step| patch_miss_step > read_step)
        .unwrap_or(true)
}

fn latest_goal_command_step(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<u32> {
    let command_literal = first_goal_command_literal(&assignment.goal)?;
    let target = normalize_whitespace(&command_literal);
    agent_state
        .command_history
        .iter()
        .rev()
        .find(|entry| {
            let observed = normalize_whitespace(&entry.command);
            observed == target || observed.contains(&target)
        })
        .map(|entry| entry.step_index)
}

fn parse_receipt_step(value: &str) -> Option<u32> {
    value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("step="))
        .and_then(|step| step.parse::<u32>().ok())
}

fn latest_workspace_edit_step(agent_state: &AgentState) -> Option<u32> {
    execution_receipt_value(&agent_state.tool_execution_log, "workspace_edit_applied")
        .and_then(parse_receipt_step)
}

fn worker_assignment_should_suppress_targeted_exec_until_workspace_edit(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
    tool_name: &str,
) -> bool {
    if !matches!(tool_name, "shell__run" | "shell__start") {
        return false;
    }
    if !matches!(
        last_failure_class,
        Some(FailureClass::UnexpectedState) | Some(FailureClass::NoEffectAfterAction)
    ) {
        return false;
    }
    let Some(assignment) = assignment else {
        return false;
    };
    if !is_patch_build_verify_assignment(Some(assignment)) {
        return false;
    }

    let Some(command_step) = latest_goal_command_step(agent_state, assignment) else {
        return false;
    };
    let latest_edit_step = latest_workspace_edit_step(agent_state);
    latest_edit_step.map_or(true, |edit_step| edit_step <= command_step)
}

fn worker_assignment_should_suppress_redundant_change_directory(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    tool_name: &str,
) -> bool {
    if tool_name != "shell__cd" {
        return false;
    }
    let Some(assignment) = assignment else {
        return false;
    };
    is_patch_build_verify_assignment(Some(assignment))
        && goal_working_directory_matches_agent_state(agent_state, assignment)
}

fn parse_recent_failure_class(entry: &str) -> Option<FailureClass> {
    let mut parts = entry.split("::");
    let _scope = parts.next()?;
    let class = parts.next()?;
    FailureClass::from_str(class)
}

pub(crate) fn worker_recovery_failure_class(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
) -> Option<FailureClass> {
    let latest = latest_failure_class(agent_state);
    if !matches!(latest, Some(FailureClass::UnexpectedState))
        || !is_patch_build_verify_assignment(assignment)
    {
        return latest;
    }

    if !agent_state.command_history.is_empty() {
        return latest;
    }

    let prior_no_effect_boundary = agent_state
        .recent_actions
        .iter()
        .rev()
        .skip(1)
        .take(3)
        .any(|entry| parse_recent_failure_class(entry) == Some(FailureClass::NoEffectAfterAction));

    if prior_no_effect_boundary {
        Some(FailureClass::NoEffectAfterAction)
    } else {
        latest
    }
}

pub(crate) fn filter_tools_for_worker_recovery(
    tools: &[LlmToolDefinition],
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
) -> Vec<LlmToolDefinition> {
    tools
        .iter()
        .filter(|tool| {
            worker_assignment_allows_tool_name_for_recovery(
                agent_state,
                assignment,
                last_failure_class,
                &tool.name,
            )
        })
        .cloned()
        .collect()
}

pub async fn execute_worker_step(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    rules: &ActionRules,
    worker_session_id: [u8; 32],
    tool: AgentTool,
    max_retries: u8,
) -> Result<WorkerExecutionResult, TransactionError> {
    let key = get_state_key(&worker_session_id);
    let bytes = state.get(&key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "Worker session not found: {}",
            hex::encode(worker_session_id)
        ))
    })?;
    let mut worker_state: AgentState = codec::from_bytes_canonical(&bytes)?;
    let os_driver = service.os_driver.clone();
    let worker_assignment =
        load_worker_assignment(state, worker_session_id).map_err(TransactionError::Invalid)?;

    let mut output: Option<String> = None;
    let mut error: Option<String> = None;
    let mut success = false;
    let mut attempts: u8 = 0;

    if let Some(assignment) = worker_assignment.as_ref() {
        let tool_name = tool.name_string();
        let last_failure_class =
            worker_recovery_failure_class(&worker_state, worker_assignment.as_ref());
        if !worker_assignment_allows_tool_name_for_recovery(
            &worker_state,
            Some(assignment),
            last_failure_class,
            &tool_name,
        ) {
            let failure = if worker_assignment_allows_tool_name(Some(assignment), &tool_name) {
                worker_assignment_recovery_disallowed_tool_error(
                    &worker_state,
                    assignment,
                    last_failure_class,
                    &tool_name,
                )
            } else {
                worker_assignment_disallowed_tool_error(assignment, &tool_name)
            };
            worker_state.step_count = worker_state.step_count.saturating_add(1);
            worker_state.status = AgentStatus::Failed(failure.clone());
            persist_agent_state(state, &key, &worker_state, service.memory_runtime.as_ref())?;
            return Ok(WorkerExecutionResult {
                success: false,
                output: None,
                error: Some(failure),
                attempts: 0,
            });
        }
    }

    // A delegated worker must never stay Running because of infrastructure gaps.
    // If no OS driver is configured, mark this worker failed and return a terminal result
    // so the parent planner can complete deterministically instead of retry-spawning.
    let Some(os_driver) = os_driver else {
        worker_state.step_count = worker_state.step_count.saturating_add(1);
        worker_state.status = AgentStatus::Failed("OS driver missing".to_string());
        persist_agent_state(state, &key, &worker_state, service.memory_runtime.as_ref())?;
        return Ok(WorkerExecutionResult {
            success: false,
            output: None,
            error: Some("OS driver missing".to_string()),
            attempts: 0,
        });
    };

    for attempt in 0..=max_retries {
        attempts = attempt.saturating_add(1);
        match service
            .handle_action_execution_with_state(
                state,
                call_context,
                tool.clone(),
                worker_session_id,
                worker_state.step_count,
                worker_state.last_screen_phash.unwrap_or([0u8; 32]),
                rules,
                &worker_state,
                &os_driver,
                None,
            )
            .await
        {
            Ok((step_success, history_entry, step_error, _step_visual_hash)) => {
                output = history_entry;
                error = step_error;
                if step_success {
                    success = true;
                    break;
                }
            }
            Err(err) => {
                error = Some(err.to_string());
            }
        }
        worker_state.consecutive_failures = worker_state.consecutive_failures.saturating_add(1);
    }

    worker_state.step_count = worker_state.step_count.saturating_add(1);
    worker_state.status = if success {
        AgentStatus::Completed(output.clone())
    } else {
        AgentStatus::Failed(
            error
                .clone()
                .unwrap_or_else(|| "worker step failed".to_string()),
        )
    };
    persist_agent_state(state, &key, &worker_state, service.memory_runtime.as_ref())?;

    Ok(WorkerExecutionResult {
        success,
        output,
        error,
        attempts,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        execute_worker_step, filter_tools_for_worker_assignment, filter_tools_for_worker_recovery,
        worker_assignment_allows_tool_name, worker_assignment_allows_tool_name_for_recovery,
        worker_assignment_disallowed_tool_error, worker_assignment_recovery_disallowed_tool_error,
        worker_recovery_failure_class,
    };
    use crate::agentic::rules::ActionRules;
    use crate::agentic::runtime::keys::get_state_key;
    use crate::agentic::runtime::service::lifecycle::{
        persist_worker_assignment, resolve_worker_assignment,
    };
    use crate::agentic::runtime::service::step::action::mark_execution_receipt_with_value;
    use crate::agentic::runtime::service::step::anti_loop::FailureClass;
    use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
    use crate::agentic::runtime::types::{
        AgentMode, AgentState, AgentStatus, ExecutionTier, WorkerAssignment,
        WorkerCompletionContract, WorkerMergeMode,
    };
    use async_trait::async_trait;
    use image::{ImageBuffer, ImageFormat, Rgba};
    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::state::StateAccess;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::agentic::LlmToolDefinition;
    use ioi_types::app::{AccountId, ChainId, ContextSlice};
    use ioi_types::codec;
    use ioi_types::error::VmError;
    use std::collections::{BTreeMap, HashMap};
    use std::io::Cursor;
    use std::sync::Arc;

    #[derive(Clone)]
    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
            img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
            let mut bytes = Vec::new();
            img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
                .map_err(|e| VmError::HostError(format!("mock PNG encode failed: {}", e)))?;
            Ok(bytes)
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            self.capture_screen(None).await
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Ok("<root/>".to_string())
        }

        async fn capture_context(
            &self,
            _intent: &ioi_types::app::ActionRequest,
        ) -> Result<ContextSlice, VmError> {
            Ok(ContextSlice {
                slice_id: [0u8; 32],
                frame_id: 0,
                chunks: vec![b"<root/>".to_vec()],
                mhnsw_root: [0u8; 32],
                traversal_proof: None,
                intent_id: [0u8; 32],
            })
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Ok(())
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn build_worker_state(session_id: [u8; 32]) -> AgentState {
        AgentState {
            session_id,
            goal: "Inspect host environment and available timer surfaces".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 4,
            last_action_type: None,
            parent_session_id: Some([9u8; 32]),
            child_session_ids: Vec::new(),
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: Vec::new(),
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: Vec::new(),
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
            pending_search_completion: None,
            planner_state: None,
        }
    }

    fn test_worker_assignment(allowed_tools: Vec<&str>) -> WorkerAssignment {
        WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 24,
            goal: "Capture a bounded worker handoff.".to_string(),
            success_criteria: "Return the requested handoff.".to_string(),
            max_retries: 0,
            retries_used: 0,
            assigned_session_id: Some([0x77; 32]),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("context_worker".to_string()),
            workflow_id: Some("repo_context_brief".to_string()),
            role: Some("Context Worker".to_string()),
            allowed_tools: allowed_tools.into_iter().map(str::to_string).collect(),
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return the requested handoff.".to_string(),
                expected_output: "Repo context brief.".to_string(),
                merge_mode: WorkerMergeMode::AppendAsEvidence,
                verification_hint: None,
            },
        }
    }

    #[test]
    fn worker_assignment_tool_filter_keeps_only_allowed_prompt_tools() {
        let assignment = test_worker_assignment(vec!["file__info", "agent__complete"]);
        let tools = vec![
            LlmToolDefinition {
                name: "file__info".to_string(),
                description: "Stat a path.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "agent__delegate".to_string(),
                description: "Delegate a child.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "agent__complete".to_string(),
                description: "Complete the worker.".to_string(),
                parameters: "{}".to_string(),
            },
        ];

        let filtered = filter_tools_for_worker_assignment(&tools, Some(&assignment));
        let filtered_names = filtered
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(filtered_names, vec!["file__info", "agent__complete"]);
        assert!(worker_assignment_allows_tool_name(
            Some(&assignment),
            "file__info"
        ));
        assert!(!worker_assignment_allows_tool_name(
            Some(&assignment),
            "agent__delegate"
        ));
        assert!(
            worker_assignment_disallowed_tool_error(&assignment, "agent__delegate")
                .contains("Worker playbook disallows tool 'agent__delegate'")
        );
    }

    #[test]
    fn worker_assignment_preserves_system_fail_escape_hatch() {
        let assignment = test_worker_assignment(vec!["file__info", "agent__complete"]);
        let tools = vec![
            LlmToolDefinition {
                name: "file__info".to_string(),
                description: "Stat a path.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "agent__escalate".to_string(),
                description: "Fail explicitly.".to_string(),
                parameters: "{}".to_string(),
            },
        ];

        let filtered = filter_tools_for_worker_assignment(&tools, Some(&assignment));
        let filtered_names = filtered
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(filtered_names, vec!["file__info", "agent__escalate"]);
        assert!(worker_assignment_allows_tool_name(
            Some(&assignment),
            "agent__escalate"
        ));
    }

    #[test]
    fn patch_build_verify_tool_filter_suppresses_discovery_after_no_effect_failure() {
        let mut assignment = test_worker_assignment(vec![
            "file__read",
            "file__write",
            "file__replace_line",
            "file__search",
            "file__list",
            "file__info",
            "file__edit",
            "shell__start",
            "agent__complete",
        ]);
        assignment.template_id = Some("coder".to_string());
        assignment.workflow_id = Some("patch_build_verify".to_string());
        assignment.role = Some("Coding Worker".to_string());

        let tools = vec![
            LlmToolDefinition {
                name: "file__read".to_string(),
                description: "Read a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__write".to_string(),
                description: "Write a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__replace_line".to_string(),
                description: "Edit one line.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__search".to_string(),
                description: "Search files.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__list".to_string(),
                description: "List a directory.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__info".to_string(),
                description: "Stat a path.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__edit".to_string(),
                description: "Patch a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "shell__start".to_string(),
                description: "Run a command.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "agent__complete".to_string(),
                description: "Complete the worker.".to_string(),
                parameters: "{}".to_string(),
            },
        ];

        let filtered = filter_tools_for_worker_recovery(
            &tools,
            &build_worker_state([0x31; 32]),
            Some(&assignment),
            Some(FailureClass::NoEffectAfterAction),
        );
        let filtered_names = filtered
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            filtered_names,
            vec![
                "file__write",
                "file__replace_line",
                "file__edit",
                "shell__start",
                "agent__complete"
            ]
        );
    }

    #[test]
    fn patch_build_verify_tool_filter_prefers_direct_reads_when_parent_context_has_likely_files() {
        let mut assignment = test_worker_assignment(vec![
            "file__read",
            "file__write",
            "file__replace_line",
            "file__search",
            "file__list",
            "file__info",
            "file__edit",
            "shell__start",
            "agent__complete",
        ]);
        assignment.template_id = Some("coder".to_string());
        assignment.workflow_id = Some("patch_build_verify".to_string());
        assignment.role = Some("Coding Worker".to_string());
        assignment.goal = "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string();

        let tools = vec![
            LlmToolDefinition {
                name: "file__read".to_string(),
                description: "Read a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__write".to_string(),
                description: "Write a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__replace_line".to_string(),
                description: "Edit one line.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__search".to_string(),
                description: "Search files.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__list".to_string(),
                description: "List a directory.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__info".to_string(),
                description: "Stat a path.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__edit".to_string(),
                description: "Patch a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "shell__start".to_string(),
                description: "Run a command.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "agent__complete".to_string(),
                description: "Complete the worker.".to_string(),
                parameters: "{}".to_string(),
            },
        ];

        let filtered = filter_tools_for_worker_recovery(
            &tools,
            &build_worker_state([0x32; 32]),
            Some(&assignment),
            None,
        );
        let filtered_names = filtered
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            filtered_names,
            vec![
                "file__read",
                "file__write",
                "file__replace_line",
                "file__edit",
                "shell__start",
                "agent__complete"
            ]
        );
    }

    #[test]
    fn patch_build_verify_tool_filter_suppresses_redundant_change_directory_when_cwd_matches_goal()
    {
        let fixture = tempfile::tempdir().expect("fixture tempdir should exist");
        let fixture_path = fixture.path().to_string_lossy().to_string();

        let mut assignment = test_worker_assignment(vec![
            "file__read",
            "file__edit",
            "shell__cd",
            "shell__start",
            "agent__complete",
        ]);
        assignment.template_id = Some("coder".to_string());
        assignment.workflow_id = Some("patch_build_verify".to_string());
        assignment.role = Some("Coding Worker".to_string());
        assignment.goal = format!(
            "Implement the parity fix in \"{}\" as a narrow workspace patch.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            fixture_path
        );

        let tools = vec![
            LlmToolDefinition {
                name: "file__read".to_string(),
                description: "Read a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__edit".to_string(),
                description: "Patch a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "shell__cd".to_string(),
                description: "Change directories.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "shell__start".to_string(),
                description: "Run a command.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "agent__complete".to_string(),
                description: "Complete the worker.".to_string(),
                parameters: "{}".to_string(),
            },
        ];

        let mut worker_state = build_worker_state([0x39; 32]);
        worker_state.working_directory = fixture_path;

        let filtered =
            filter_tools_for_worker_recovery(&tools, &worker_state, Some(&assignment), None);
        let filtered_names = filtered
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            filtered_names,
            vec![
                "file__read",
                "file__edit",
                "shell__start",
                "agent__complete"
            ]
        );
        assert!(!worker_assignment_allows_tool_name_for_recovery(
            &worker_state,
            Some(&assignment),
            None,
            "shell__cd"
        ));
    }

    #[test]
    fn patch_build_verify_recovery_blocks_repeated_file_reads_at_execution_boundary() {
        let mut assignment = test_worker_assignment(vec![
            "file__read",
            "file__write",
            "file__replace_line",
            "file__search",
            "file__list",
            "file__info",
            "file__edit",
            "shell__start",
            "agent__complete",
        ]);
        assignment.template_id = Some("coder".to_string());
        assignment.workflow_id = Some("patch_build_verify".to_string());
        assignment.role = Some("Coding Worker".to_string());

        assert!(!worker_assignment_allows_tool_name_for_recovery(
            &build_worker_state([0x33; 32]),
            Some(&assignment),
            Some(FailureClass::NoEffectAfterAction),
            "file__read"
        ));
        let failure = worker_assignment_recovery_disallowed_tool_error(
            &build_worker_state([0x34; 32]),
            &assignment,
            Some(FailureClass::NoEffectAfterAction),
            "file__read",
        );
        assert!(failure.contains("NoEffectAfterAction"));
        assert!(failure.contains("file__edit"));
        assert!(failure.contains("file__replace_line"));
        assert!(!failure.contains("file__read,"));
    }

    #[test]
    fn patch_build_verify_recovery_preserves_duplicate_read_boundary_after_invalid_tool_call() {
        let mut assignment = test_worker_assignment(vec![
            "file__read",
            "file__write",
            "file__replace_line",
            "file__search",
            "file__list",
            "file__info",
            "file__edit",
            "shell__start",
            "agent__complete",
        ]);
        assignment.template_id = Some("coder".to_string());
        assignment.workflow_id = Some("patch_build_verify".to_string());
        assignment.role = Some("Coding Worker".to_string());
        assignment.goal = "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string();

        let mut worker_state = build_worker_state([0x44; 32]);
        worker_state.recent_actions = vec![
            "attempt::NoEffectAfterAction::first".to_string(),
            "attempt::UnexpectedState::second".to_string(),
        ];

        let effective_failure = worker_recovery_failure_class(&worker_state, Some(&assignment));
        assert_eq!(effective_failure, Some(FailureClass::NoEffectAfterAction));

        let tools = vec![
            LlmToolDefinition {
                name: "file__read".to_string(),
                description: "Read a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__write".to_string(),
                description: "Write a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__replace_line".to_string(),
                description: "Edit one line.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__search".to_string(),
                description: "Search files.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__list".to_string(),
                description: "List a directory.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__info".to_string(),
                description: "Stat a path.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__edit".to_string(),
                description: "Patch a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "shell__start".to_string(),
                description: "Run a command.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "agent__complete".to_string(),
                description: "Complete the worker.".to_string(),
                parameters: "{}".to_string(),
            },
        ];

        let filtered = filter_tools_for_worker_recovery(
            &tools,
            &worker_state,
            Some(&assignment),
            effective_failure,
        );
        let filtered_names = filtered
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            filtered_names,
            vec![
                "file__write",
                "file__replace_line",
                "file__edit",
                "shell__start",
                "agent__complete"
            ]
        );
    }

    #[test]
    fn patch_build_verify_recovery_resets_duplicate_read_boundary_after_command_history() {
        let mut assignment = test_worker_assignment(vec![
            "file__read",
            "file__write",
            "file__replace_line",
            "file__search",
            "file__list",
            "file__info",
            "file__edit",
            "shell__start",
            "agent__complete",
        ]);
        assignment.template_id = Some("coder".to_string());
        assignment.workflow_id = Some("patch_build_verify".to_string());
        assignment.role = Some("Coding Worker".to_string());
        assignment.goal = "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string();

        let mut worker_state = build_worker_state([0x55; 32]);
        worker_state.recent_actions = vec![
            "attempt::NoEffectAfterAction::first".to_string(),
            "attempt::UnexpectedState::second".to_string(),
        ];
        worker_state
            .command_history
            .push_back(crate::agentic::runtime::types::CommandExecution {
                command: "python3 -m unittest tests.test_path_utils -v".to_string(),
                exit_code: 1,
                stdout: "failing test output".to_string(),
                stderr: String::new(),
                timestamp_ms: 1,
                step_index: 3,
            });

        let effective_failure = worker_recovery_failure_class(&worker_state, Some(&assignment));
        assert_eq!(effective_failure, Some(FailureClass::UnexpectedState));
    }

    #[test]
    fn patch_build_verify_recovery_blocks_targeted_exec_rerun_until_workspace_edit_receipt() {
        let mut assignment = test_worker_assignment(vec![
            "file__read",
            "file__write",
            "file__replace_line",
            "file__search",
            "file__list",
            "file__info",
            "file__edit",
            "shell__start",
            "agent__complete",
        ]);
        assignment.template_id = Some("coder".to_string());
        assignment.workflow_id = Some("patch_build_verify".to_string());
        assignment.role = Some("Coding Worker".to_string());
        assignment.goal = "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string();

        let tools = vec![
            LlmToolDefinition {
                name: "file__read".to_string(),
                description: "Read a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__write".to_string(),
                description: "Write a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__replace_line".to_string(),
                description: "Edit one line.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__search".to_string(),
                description: "Search files.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__list".to_string(),
                description: "List a directory.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__info".to_string(),
                description: "Stat a path.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__edit".to_string(),
                description: "Patch a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "shell__start".to_string(),
                description: "Run a command.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "agent__complete".to_string(),
                description: "Complete the worker.".to_string(),
                parameters: "{}".to_string(),
            },
        ];

        let mut worker_state = build_worker_state([0x66; 32]);
        worker_state
            .command_history
            .push_back(crate::agentic::runtime::types::CommandExecution {
                command: "python3 -m unittest tests.test_path_utils -v".to_string(),
                exit_code: 1,
                stdout: "failing test output".to_string(),
                stderr: String::new(),
                timestamp_ms: 1,
                step_index: 5,
            });

        let filtered = filter_tools_for_worker_recovery(
            &tools,
            &worker_state,
            Some(&assignment),
            Some(FailureClass::UnexpectedState),
        );
        let filtered_names = filtered
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            filtered_names,
            vec![
                "file__read",
                "file__write",
                "file__replace_line",
                "file__edit",
                "agent__complete"
            ]
        );
    }

    #[test]
    fn patch_build_verify_recovery_restores_targeted_exec_after_workspace_edit_receipt() {
        let mut assignment = test_worker_assignment(vec![
            "file__read",
            "file__write",
            "file__replace_line",
            "file__search",
            "file__list",
            "file__info",
            "file__edit",
            "shell__start",
            "agent__complete",
        ]);
        assignment.template_id = Some("coder".to_string());
        assignment.workflow_id = Some("patch_build_verify".to_string());
        assignment.role = Some("Coding Worker".to_string());
        assignment.goal = "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string();

        let tools = vec![
            LlmToolDefinition {
                name: "file__read".to_string(),
                description: "Read a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__write".to_string(),
                description: "Write a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__replace_line".to_string(),
                description: "Edit one line.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__search".to_string(),
                description: "Search files.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__list".to_string(),
                description: "List a directory.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__info".to_string(),
                description: "Stat a path.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "file__edit".to_string(),
                description: "Patch a file.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "shell__start".to_string(),
                description: "Run a command.".to_string(),
                parameters: "{}".to_string(),
            },
            LlmToolDefinition {
                name: "agent__complete".to_string(),
                description: "Complete the worker.".to_string(),
                parameters: "{}".to_string(),
            },
        ];

        let mut worker_state = build_worker_state([0x67; 32]);
        worker_state
            .command_history
            .push_back(crate::agentic::runtime::types::CommandExecution {
                command: "python3 -m unittest tests.test_path_utils -v".to_string(),
                exit_code: 1,
                stdout: "failing test output".to_string(),
                stderr: String::new(),
                timestamp_ms: 1,
                step_index: 5,
            });
        mark_execution_receipt_with_value(
            &mut worker_state.tool_execution_log,
            "workspace_edit_applied",
            "step=6;tool=file__edit;path=path_utils.py".to_string(),
        );

        let filtered = filter_tools_for_worker_recovery(
            &tools,
            &worker_state,
            Some(&assignment),
            Some(FailureClass::UnexpectedState),
        );
        let filtered_names = filtered
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            filtered_names,
            vec![
                "file__read",
                "file__write",
                "file__replace_line",
                "file__edit",
                "shell__start",
                "agent__complete"
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_os_driver_marks_worker_failed_instead_of_leaving_running() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let runtime = Arc::new(MockInferenceRuntime);
        let mut service = RuntimeAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime,
        );
        service.os_driver = None;

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let worker_session_id = [0x11; 32];
        let key = get_state_key(&worker_session_id);
        let worker_state = build_worker_state(worker_session_id);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");

        let services_dir = ServiceDirectory::new(vec![]);
        let call_context = ServiceCallContext {
            block_height: 1,
            block_timestamp: 1,
            chain_id: ChainId(0),
            signer_account_id: AccountId::default(),
            services: &services_dir,
            simulation: false,
            is_internal: false,
        };

        let result = execute_worker_step(
            &service,
            &mut state,
            call_context,
            &ActionRules::default(),
            worker_session_id,
            ioi_types::app::agentic::AgentTool::OsLaunchApp {
                app_name: "calculator".to_string(),
            },
            1,
        )
        .await
        .expect("worker execution should return terminal result");

        assert!(!result.success);
        assert_eq!(result.attempts, 0);
        assert_eq!(result.error.as_deref(), Some("OS driver missing"));

        let bytes = state
            .get(&key)
            .expect("state get")
            .expect("worker state should exist");
        let updated: AgentState = codec::from_bytes_canonical(&bytes).expect("decode worker state");
        assert!(matches!(updated.status, AgentStatus::Failed(_)));
        assert_eq!(updated.step_count, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verifier_playbook_blocks_disallowed_worker_tool_execution() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let runtime = Arc::new(MockInferenceRuntime);
        let mut service = RuntimeAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime,
        );
        service.os_driver = None;

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let worker_session_id = [0x22; 32];
        let key = get_state_key(&worker_session_id);
        let worker_state = build_worker_state(worker_session_id);
        state
            .insert(
                &key,
                &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
            )
            .expect("insert worker state");
        let assignment = resolve_worker_assignment(
            worker_session_id,
            1,
            90,
            "Verify whether the receipt proves the claimed postcondition.",
            None,
            Some("verifier"),
            Some("postcondition_audit"),
            None,
            None,
            None,
            None,
        );
        persist_worker_assignment(&mut state, worker_session_id, &assignment)
            .expect("persist worker assignment");

        let services_dir = ServiceDirectory::new(vec![]);
        let call_context = ServiceCallContext {
            block_height: 1,
            block_timestamp: 1,
            chain_id: ChainId(0),
            signer_account_id: AccountId::default(),
            services: &services_dir,
            simulation: false,
            is_internal: false,
        };

        let result = execute_worker_step(
            &service,
            &mut state,
            call_context,
            &ActionRules::default(),
            worker_session_id,
            ioi_types::app::agentic::AgentTool::Dynamic(serde_json::json!({
                "tool_name": "model__responses",
                "input": [{ "role": "user", "content": "audit the receipt" }]
            })),
            assignment.max_retries,
        )
        .await
        .expect("worker execution should return terminal result");

        assert!(!result.success);
        assert_eq!(result.attempts, 0);
        assert!(result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("Worker playbook disallows tool 'model__responses'"));
    }
}
