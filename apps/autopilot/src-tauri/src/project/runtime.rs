// apps/autopilot/src-tauri/src/project/runtime.rs

use super::workflow_approval_interrupt_lane::{
    workflow_runtime_approval_preview, workflow_runtime_interrupt,
    workflow_runtime_interrupt_notice,
};
use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_coding_route_lane::WorkflowSkillResolver;
use super::workflow_execution_results_lane::{
    workflow_completion_has_missing, workflow_completion_requirements,
    workflow_finalize_run_result, WorkflowRunResultParts,
};
use super::workflow_graph_execution_lane::{
    workflow_edge_connection_class, workflow_edge_from_port, workflow_edge_to_port,
    workflow_next_ready_nodes, workflow_node_lifecycle_steps,
};
use super::workflow_harness_results_lane::workflow_attach_harness_run_artifacts;
use super::workflow_state_lane::{workflow_predecessor_output, workflow_selected_output};
use super::workflow_value_helpers::{
    workflow_logic_string, workflow_value_bool_any, workflow_value_string_any,
};
use super::*;

pub(super) fn workflow_value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

pub(super) fn workflow_node_id(node: &Value) -> Option<String> {
    workflow_value_string(node, "id")
}

pub(super) fn workflow_node_type(node: &Value) -> String {
    workflow_value_string(node, "type").unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn workflow_node_name(node: &Value) -> String {
    workflow_value_string(node, "name").unwrap_or_else(|| "Workflow step".to_string())
}

pub(super) fn workflow_node_logic(node: &Value) -> Value {
    node.get("config")
        .and_then(|config| config.get("logic"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

pub(super) fn workflow_node_law(node: &Value) -> Value {
    node.get("config")
        .and_then(|config| config.get("law"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

pub(super) fn workflow_action_frame(node: &Value) -> ActionFrame {
    let node_id = workflow_node_id(node).unwrap_or_else(|| "unknown".to_string());
    let logic = workflow_node_logic(node);
    let law = workflow_node_law(node);
    let kind = ActionKind::from_node_type(&workflow_node_type(node));
    let binding = match kind {
        ActionKind::ModelCall => Some(ActionBindingRef {
            binding_type: "model".to_string(),
            reference: logic
                .get("modelRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: false,
            side_effect_class: "compute".to_string(),
            requires_approval: false,
        }),
        ActionKind::ModelBinding => Some(ActionBindingRef {
            binding_type: "model".to_string(),
            reference: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("modelRef"))
                .and_then(Value::as_str)
                .or_else(|| logic.get("modelRef").and_then(Value::as_str))
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("mockBinding"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
            side_effect_class: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("sideEffectClass"))
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_string(),
            requires_approval: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("requiresApproval"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::Parser => Some(ActionBindingRef {
            binding_type: "parser".to_string(),
            reference: logic
                .get("parserBinding")
                .and_then(|binding| binding.get("parserRef"))
                .and_then(Value::as_str)
                .or_else(|| logic.get("parserRef").and_then(Value::as_str))
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: logic
                .get("parserBinding")
                .and_then(|binding| binding.get("mockBinding"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
            side_effect_class: "none".to_string(),
            requires_approval: false,
        }),
        ActionKind::Function => Some(ActionBindingRef {
            binding_type: "function".to_string(),
            reference: logic
                .get("functionBinding")
                .and_then(|binding| binding.get("language"))
                .and_then(Value::as_str)
                .or_else(|| logic.get("language").and_then(Value::as_str))
                .map(str::to_string),
            mock_binding: false,
            side_effect_class: "compute".to_string(),
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::WorkflowPackageExport => Some(ActionBindingRef {
            binding_type: "workflow_package".to_string(),
            reference: workflow_logic_string(&logic, "workflowPackagePath"),
            mock_binding: false,
            side_effect_class: "write".to_string(),
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::WorkflowPackageImport => Some(ActionBindingRef {
            binding_type: "workflow_package".to_string(),
            reference: workflow_logic_string(&logic, "workflowPackagePath"),
            mock_binding: false,
            side_effect_class: "write".to_string(),
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::GithubPrCreate => Some(ActionBindingRef {
            binding_type: "github".to_string(),
            reference: workflow_value_string_any(&logic, &["repoFullName", "repository"]),
            mock_binding: true,
            side_effect_class: "external_write".to_string(),
            requires_approval: !workflow_value_bool_any(&logic, &["dryRun", "previewOnly"])
                .unwrap_or(true),
        }),
        ActionKind::AdapterConnector => {
            logic
                .get("connectorBinding")
                .map(|binding| ActionBindingRef {
                    binding_type: "connector".to_string(),
                    reference: binding
                        .get("connectorRef")
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .map(str::to_string),
                    mock_binding: binding
                        .get("mockBinding")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    side_effect_class: binding
                        .get("sideEffectClass")
                        .and_then(Value::as_str)
                        .unwrap_or("read")
                        .to_string(),
                    requires_approval: binding
                        .get("requiresApproval")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
        }
        ActionKind::PluginTool => logic.get("toolBinding").map(|binding| ActionBindingRef {
            binding_type: "tool".to_string(),
            reference: binding
                .get("toolRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: binding
                .get("mockBinding")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            side_effect_class: binding
                .get("sideEffectClass")
                .and_then(Value::as_str)
                .unwrap_or("read")
                .to_string(),
            requires_approval: binding
                .get("requiresApproval")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        _ => None,
    };
    let privileged_actions = law
        .get("privilegedActions")
        .or_else(|| logic.get("privilegedActions"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let sandbox_permissions = law
        .get("sandboxPolicy")
        .and_then(|policy| policy.get("permissions"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ActionFrame {
        id: node_id,
        surface: ActionSurface::Workflow,
        kind,
        label: workflow_node_name(node),
        binding,
        policy: ActionPolicy {
            privileged_actions,
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            sandbox_permissions,
        },
        metadata: std::collections::BTreeMap::new(),
    }
}

pub(super) fn workflow_node_port_connection_class(
    node: &Value,
    port_id: &str,
    direction: &str,
) -> Option<String> {
    if let Some(class) = node
        .get("ports")
        .and_then(Value::as_array)
        .and_then(|ports| {
            ports.iter().find(|port| {
                port.get("id").and_then(Value::as_str) == Some(port_id)
                    && port.get("direction").and_then(Value::as_str) == Some(direction)
            })
        })
        .and_then(|port| port.get("connectionClass").and_then(Value::as_str))
        .map(str::to_string)
    {
        return Some(class);
    }
    workflow_default_port_connection_class(&workflow_node_type(node), port_id, direction)
}

pub(super) fn workflow_default_port_connection_class(
    node_type: &str,
    port_id: &str,
    direction: &str,
) -> Option<String> {
    let class = match (node_type, direction, port_id) {
        (_, "output", "error") | (_, "input", "error") => "error",
        (_, "output", "retry") | (_, "input", "retry") => "retry",
        (_, "output", "approval") | (_, "input", "approval") => "approval",
        ("model_call", "input", "model") | ("model_binding", "output", "model") => "model",
        ("model_call", "input", "memory") | ("state", "output", "memory") => "memory",
        ("model_call", "input", "tool")
        | ("plugin_tool", "output", "tool")
        | ("subgraph", "output", "tool") => "tool",
        ("workflow_package_export", "output", "package")
        | ("workflow_package_import", "input", "package") => "output_bundle",
        ("workflow_package_export", "output", "manifest")
        | ("workflow_package_export", "output", "readiness")
        | ("workflow_package_export", "output", "locale")
        | ("workflow_package_import", "output", "review")
        | ("workflow_package_import", "output", "imported_workflow")
        | ("workflow_package_import", "output", "evidence")
        | ("workflow_package_import", "output", "locale") => "data",
        ("repository_context", "output", "repository")
        | ("branch_policy", "input", "repository")
        | ("branch_policy", "output", "branch_policy")
        | ("github_context", "input", "repository")
        | ("github_context", "input", "branch_policy")
        | ("github_context", "output", "github_context")
        | ("issue_context", "input", "github_context")
        | ("issue_context", "output", "issue_context")
        | ("pr_attempt", "input", "repository")
        | ("pr_attempt", "input", "branch_policy")
        | ("pr_attempt", "input", "github_context")
        | ("pr_attempt", "input", "issue_context")
        | ("pr_attempt", "output", "pr_attempt")
        | ("review_gate", "input", "repository")
        | ("review_gate", "input", "branch_policy")
        | ("review_gate", "input", "github_context")
        | ("review_gate", "input", "issue_context")
        | ("review_gate", "input", "pr_attempt")
        | ("github_pr_create", "input", "repository")
        | ("github_pr_create", "input", "branch_policy")
        | ("github_pr_create", "input", "github_context")
        | ("github_pr_create", "input", "issue_context")
        | ("github_pr_create", "input", "pr_attempt")
        | ("github_pr_create", "output", "blockers") => "state",
        ("review_gate", "output", "review_gate")
        | ("github_pr_create", "input", "review_gate")
        | ("github_pr_create", "output", "plan") => "approval",
        ("github_pr_create", "output", "request") => "data",
        ("model_call", "input", "parser") | ("parser", "output", "parser") => "parser",
        ("subgraph", "input", "subgraph") | ("subgraph", "output", "subgraph") => "subgraph",
        ("output", "input", "delivery") => "delivery",
        (_, _, "input")
        | (_, _, "context")
        | (_, _, "output")
        | (_, _, "left")
        | (_, _, "right") => "data",
        _ => return None,
    };
    Some(class.to_string())
}

pub(super) fn validate_workflow_edge_ports(
    edge: &Value,
    from_node: &Value,
    to_node: &Value,
) -> Result<(), WorkflowValidationIssue> {
    let edge_id = edge.get("id").and_then(Value::as_str).unwrap_or("unknown");
    let from_port = workflow_edge_from_port(edge);
    let to_port = workflow_edge_to_port(edge);
    let source_class = workflow_node_port_connection_class(from_node, &from_port, "output")
        .or_else(|| workflow_edge_connection_class(edge))
        .unwrap_or_else(|| "data".to_string());
    let target_class = workflow_node_port_connection_class(to_node, &to_port, "input")
        .unwrap_or_else(|| {
            workflow_edge_connection_class(edge).unwrap_or_else(|| "data".to_string())
        });
    validate_workflow_connection_class(Some(edge_id.to_string()), &source_class, &target_class)
        .map_err(|issue| WorkflowValidationIssue {
            node_id: issue.action_id,
            code: issue.code,
            message: issue.message,
        })
}

pub(super) fn workflow_node_by_id<'a>(
    workflow: &'a WorkflowProject,
    node_id: &str,
) -> Option<&'a Value> {
    workflow
        .nodes
        .iter()
        .find(|node| workflow_node_id(node).as_deref() == Some(node_id))
}

pub(super) fn workflow_max_attempts(node: &Value) -> usize {
    let logic = workflow_node_logic(node);
    let law = workflow_node_law(node);
    logic
        .get("retry")
        .and_then(|retry| retry.get("maxAttempts"))
        .or_else(|| {
            law.get("retryPolicy")
                .and_then(|retry| retry.get("maxAttempts"))
        })
        .and_then(Value::as_u64)
        .map(|value| value.clamp(1, 5) as usize)
        .unwrap_or(1)
}

pub(super) fn workflow_push_event(
    events: &mut Vec<WorkflowStreamEvent>,
    run_id: &str,
    thread_id: &str,
    kind: &str,
    node_id: Option<&str>,
    status: Option<&str>,
    message: Option<String>,
    state_delta: Option<Vec<WorkflowStateUpdate>>,
) {
    let sequence = events.len();
    events.push(WorkflowStreamEvent {
        id: unique_runtime_id("event"),
        run_id: run_id.to_string(),
        thread_id: thread_id.to_string(),
        sequence,
        kind: kind.to_string(),
        created_at_ms: now_ms(),
        node_id: node_id.map(str::to_string),
        status: status.map(str::to_string),
        message,
        state_delta,
    });
}

pub(super) fn execute_workflow_project(
    workflow_path: &Path,
    bundle: WorkflowWorkbenchBundle,
    thread: WorkflowThread,
    mut state: WorkflowStateSnapshot,
    resume_gate: Option<(String, Value)>,
    skill_resolver: &WorkflowSkillResolver,
) -> Result<WorkflowRunResult, String> {
    let started_at_ms = now_ms();
    let run_id = unique_runtime_id("workflow-run");
    let thread_id = thread.id.clone();
    state.run_id = run_id.clone();
    let validation = validate_workflow_project_bundle(&bundle.workflow, &bundle.tests);
    let mut events = Vec::new();
    let mut checkpoints = Vec::new();
    let mut node_runs = Vec::new();
    let mut completed = state
        .completed_node_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut active_queue = if state.active_node_ids.is_empty() {
        workflow_next_ready_nodes(&bundle.workflow, &completed, &[], &state.branch_decisions)
    } else {
        state.active_node_ids.clone()
    };

    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_started",
        None,
        Some("running"),
        Some("Workflow run started.".to_string()),
        None,
    );

    if validation.status != "passed" {
        state.blocked_node_ids = validation.blocked_nodes.clone();
        let checkpoint_id = workflow_checkpoint_state(
            workflow_path,
            &mut state,
            &run_id,
            &thread_id,
            None,
            &validation.status,
            format!(
                "Workflow blocked by {} validation issue(s).",
                validation.blocked_nodes.len()
            ),
            &mut checkpoints,
        )?;
        let summary = WorkflowRunSummary {
            id: run_id.clone(),
            thread_id: Some(thread_id.clone()),
            status: validation.status.clone(),
            started_at_ms,
            finished_at_ms: Some(now_ms()),
            node_count: bundle.workflow.nodes.len(),
            test_count: Some(bundle.tests.len()),
            checkpoint_count: Some(checkpoints.len()),
            interrupt_id: None,
            summary: format!(
                "Workflow blocked by {} validation issue(s).",
                validation.errors.len() + validation.warnings.len()
            ),
            evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
        };
        workflow_push_event(
            &mut events,
            &run_id,
            &thread_id,
            "run_completed",
            None,
            Some(&summary.status),
            Some(summary.summary.clone()),
            None,
        );
        let mut final_thread = thread.clone();
        final_thread.status = summary.status.clone();
        final_thread.latest_checkpoint_id = Some(checkpoint_id);
        let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
            workflow_attach_harness_run_artifacts(&bundle.workflow, &run_id, &mut node_runs);
        let completion_requirements =
            workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
        let result = workflow_finalize_run_result(
            workflow_path,
            &bundle.workflow,
            WorkflowRunResultParts {
                summary,
                thread: final_thread,
                final_state: state,
                node_runs,
                checkpoints,
                events,
                harness_attempts,
                harness_shadow_comparisons,
                harness_gated_cluster_runs,
                completion_requirements,
                interrupt: None,
            },
        )?;
        return Ok(result);
    }

    let max_steps = bundle.workflow.nodes.len().saturating_mul(4).max(1);
    let mut steps = 0usize;
    while let Some(node_id) = active_queue.first().cloned() {
        active_queue.remove(0);
        if completed.contains(&node_id) {
            continue;
        }
        steps += 1;
        if steps > max_steps {
            state.blocked_node_ids.push(node_id.clone());
            break;
        }
        let Some(node) = workflow_node_by_id(&bundle.workflow, &node_id) else {
            state.blocked_node_ids.push(node_id.clone());
            continue;
        };
        let node_type = workflow_node_type(node);
        let action_kind = ActionKind::from_node_type(&node_type);
        let input = workflow_predecessor_output(&node_id, &bundle.workflow, &state);
        let resume_matches_node =
            resume_gate.as_ref().map(|(id, _)| id.as_str()) == Some(node_id.as_str());
        let runtime_approval_preview =
            workflow_runtime_approval_preview(node, &action_kind, &input);
        if (action_kind.is_interrupt() || runtime_approval_preview.is_some())
            && !resume_matches_node
        {
            let interrupt = workflow_runtime_interrupt(
                &run_id,
                &thread_id,
                node,
                &action_kind,
                runtime_approval_preview,
            );
            let interrupt_id = interrupt.id.clone();
            state.interrupted_node_ids.push(node_id.clone());
            state.active_node_ids = active_queue.clone();
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread_id,
                Some(&node_id),
                "interrupted",
                format!("Run paused at '{}'.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "node_interrupted",
                Some(&node_id),
                Some("interrupted"),
                Some(workflow_runtime_interrupt_notice(&action_kind)),
                None,
            );
            node_runs.push(WorkflowNodeRun {
                node_id: node_id.clone(),
                node_type: node_type.clone(),
                status: "interrupted".to_string(),
                started_at_ms: now_ms(),
                finished_at_ms: Some(now_ms()),
                attempt: 1,
                input: Some(input.clone()),
                output: None,
                error: None,
                checkpoint_id: Some(checkpoint_id.clone()),
                lifecycle: workflow_node_lifecycle_steps("interrupted"),
                harness_attempt: None,
            });
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "run_completed",
                None,
                Some("interrupted"),
                Some("Run paused for human input.".to_string()),
                None,
            );
            fs::create_dir_all(workflow_interrupts_dir(workflow_path))
                .map_err(|error| format!("Failed to create interrupts directory: {}", error))?;
            write_json_pretty(&workflow_interrupt_path(workflow_path, &run_id), &interrupt)?;
            let summary = WorkflowRunSummary {
                id: run_id.clone(),
                thread_id: Some(thread_id.clone()),
                status: "interrupted".to_string(),
                started_at_ms,
                finished_at_ms: Some(now_ms()),
                node_count: bundle.workflow.nodes.len(),
                test_count: Some(bundle.tests.len()),
                checkpoint_count: Some(checkpoints.len()),
                interrupt_id: Some(interrupt_id.clone()),
                summary: format!("Run paused at '{}'.", workflow_node_name(node)),
                evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
            };
            let mut final_thread = thread.clone();
            final_thread.status = "interrupted".to_string();
            final_thread.latest_checkpoint_id = Some(checkpoint_id);
            save_workflow_thread(workflow_path, &final_thread)?;
            let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
                workflow_attach_harness_run_artifacts(&bundle.workflow, &run_id, &mut node_runs);
            let completion_requirements =
                workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
            let result = workflow_finalize_run_result(
                workflow_path,
                &bundle.workflow,
                WorkflowRunResultParts {
                    summary,
                    thread: final_thread,
                    final_state: state,
                    node_runs,
                    checkpoints,
                    events,
                    harness_attempts,
                    harness_shadow_comparisons,
                    harness_gated_cluster_runs,
                    completion_requirements,
                    interrupt: Some(interrupt),
                },
            )?;
            return Ok(result);
        }

        let mut node_run = WorkflowNodeRun {
            node_id: node_id.clone(),
            node_type: node_type.clone(),
            status: "running".to_string(),
            started_at_ms: now_ms(),
            finished_at_ms: None,
            attempt: 1,
            input: Some(input.clone()),
            output: None,
            error: None,
            checkpoint_id: None,
            lifecycle: Vec::new(),
            harness_attempt: None,
        };
        workflow_push_event(
            &mut events,
            &run_id,
            &thread_id,
            "node_started",
            Some(&node_id),
            Some("running"),
            Some(format!("{} started.", workflow_node_name(node))),
            None,
        );
        let max_attempts = workflow_max_attempts(node);
        let mut execution_result = Err("Node did not execute.".to_string());
        for attempt in 1..=max_attempts {
            node_run.attempt = attempt;
            let resume_value = resume_gate
                .as_ref()
                .and_then(|(resume_node_id, value)| (resume_node_id == &node_id).then_some(value));
            execution_result = execute_workflow_node(
                workflow_path,
                Some(&bundle.workflow),
                node,
                input.clone(),
                attempt,
                resume_value,
                skill_resolver,
            );
            if execution_result.is_ok() || attempt == max_attempts {
                break;
            }
            node_runs.push(WorkflowNodeRun {
                node_id: node_id.clone(),
                node_type: node_type.clone(),
                status: "error".to_string(),
                started_at_ms: node_run.started_at_ms,
                finished_at_ms: Some(now_ms()),
                attempt,
                input: Some(input.clone()),
                output: None,
                error: execution_result.as_ref().err().cloned(),
                checkpoint_id: None,
                lifecycle: workflow_node_lifecycle_steps("error"),
                harness_attempt: None,
            });
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "node_failed",
                Some(&node_id),
                Some("retrying"),
                Some(format!(
                    "Retrying '{}' after attempt {}.",
                    workflow_node_name(node),
                    attempt
                )),
                None,
            );
        }

        match execution_result {
            Ok(output) => {
                let selected_output = workflow_selected_output(node, &output);
                if action_kind == ActionKind::Decision {
                    state
                        .branch_decisions
                        .insert(node_id.clone(), selected_output.clone());
                }
                completed.insert(node_id.clone());
                state.completed_node_ids = completed.iter().cloned().collect();
                state.interrupted_node_ids.retain(|id| id != &node_id);
                state.node_outputs.insert(node_id.clone(), output.clone());
                let update = if action_kind == ActionKind::State {
                    let key = output
                        .get("stateKey")
                        .and_then(Value::as_str)
                        .unwrap_or(&node_id)
                        .to_string();
                    let reducer = output
                        .get("reducer")
                        .and_then(Value::as_str)
                        .unwrap_or("replace")
                        .to_string();
                    let value = output
                        .get("value")
                        .cloned()
                        .unwrap_or_else(|| output.clone());
                    match reducer.as_str() {
                        "merge" => {
                            let mut merged = state
                                .values
                                .get(&key)
                                .cloned()
                                .or_else(|| workflow_node_logic(node).get("initialValue").cloned())
                                .unwrap_or_else(|| json!({}));
                            if let (Some(current), Some(next)) =
                                (merged.as_object_mut(), value.as_object())
                            {
                                for (item_key, item_value) in next {
                                    current.insert(item_key.clone(), item_value.clone());
                                }
                                state.values.insert(key.clone(), merged.clone());
                            } else {
                                state.values.insert(key.clone(), value.clone());
                            }
                        }
                        "append" => {
                            let mut list = state
                                .values
                                .get(&key)
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default();
                            list.push(value.clone());
                            state.values.insert(key.clone(), Value::Array(list));
                        }
                        _ => {
                            state.values.insert(key.clone(), value.clone());
                        }
                    }
                    WorkflowStateUpdate {
                        node_id: node_id.clone(),
                        key,
                        value,
                        reducer,
                    }
                } else {
                    state.values.insert(node_id.clone(), output.clone());
                    WorkflowStateUpdate {
                        node_id: node_id.clone(),
                        key: node_id.clone(),
                        value: output.clone(),
                        reducer: "replace".to_string(),
                    }
                };
                state.pending_writes.clear();
                state.step_index += 1;
                active_queue.extend(workflow_next_ready_nodes(
                    &bundle.workflow,
                    &completed,
                    &active_queue,
                    &state.branch_decisions,
                ));
                state.active_node_ids = active_queue.clone();
                let checkpoint_id = workflow_checkpoint_state(
                    workflow_path,
                    &mut state,
                    &run_id,
                    &thread_id,
                    Some(&node_id),
                    "running",
                    format!("{} completed.", workflow_node_name(node)),
                    &mut checkpoints,
                )?;
                node_run.status = "success".to_string();
                node_run.finished_at_ms = Some(now_ms());
                node_run.output = Some(output.clone());
                node_run.checkpoint_id = Some(checkpoint_id);
                node_run.lifecycle = workflow_node_lifecycle_steps("success");
                workflow_push_event(
                    &mut events,
                    &run_id,
                    &thread_id,
                    "node_succeeded",
                    Some(&node_id),
                    Some("success"),
                    Some(format!("{} completed.", workflow_node_name(node))),
                    Some(vec![update]),
                );
                if output.get("toolKind").and_then(Value::as_str) == Some("workflow_tool") {
                    let child_run_id = output
                        .get("childRunId")
                        .and_then(Value::as_str)
                        .unwrap_or("child run");
                    let child_status = output
                        .get("childRunStatus")
                        .and_then(Value::as_str)
                        .unwrap_or("completed");
                    workflow_push_event(
                        &mut events,
                        &run_id,
                        &thread_id,
                        "child_run_completed",
                        Some(&node_id),
                        Some(child_status),
                        Some(format!(
                            "{} completed child workflow run {}.",
                            workflow_node_name(node),
                            child_run_id
                        )),
                        None,
                    );
                }
                if action_kind == ActionKind::Output {
                    workflow_push_event(
                        &mut events,
                        &run_id,
                        &thread_id,
                        "output_created",
                        Some(&node_id),
                        Some("success"),
                        Some(format!(
                            "{} produced an output bundle.",
                            workflow_node_name(node)
                        )),
                        None,
                    );
                    if output
                        .get("outputBundle")
                        .and_then(|bundle| bundle.get("materializedAssets"))
                        .and_then(Value::as_array)
                        .map(|assets| !assets.is_empty())
                        .unwrap_or(false)
                    {
                        workflow_push_event(
                            &mut events,
                            &run_id,
                            &thread_id,
                            "asset_materialized",
                            Some(&node_id),
                            Some("success"),
                            Some(format!(
                                "{} recorded a materialized asset.",
                                workflow_node_name(node)
                            )),
                            None,
                        );
                    }
                }
                node_runs.push(node_run);
            }
            Err(error) => {
                state.blocked_node_ids.push(node_id.clone());
                state.step_index += 1;
                state.active_node_ids = active_queue.clone();
                let checkpoint_id = workflow_checkpoint_state(
                    workflow_path,
                    &mut state,
                    &run_id,
                    &thread_id,
                    Some(&node_id),
                    "failed",
                    format!("{} failed.", workflow_node_name(node)),
                    &mut checkpoints,
                )?;
                node_run.status = "error".to_string();
                node_run.finished_at_ms = Some(now_ms());
                node_run.error = Some(error.clone());
                node_run.checkpoint_id = Some(checkpoint_id);
                node_run.lifecycle = workflow_node_lifecycle_steps("error");
                node_runs.push(node_run);
                workflow_push_event(
                    &mut events,
                    &run_id,
                    &thread_id,
                    "node_failed",
                    Some(&node_id),
                    Some("error"),
                    Some(error),
                    None,
                );
                break;
            }
        }
    }

    let mut status = if !state.blocked_node_ids.is_empty() {
        "failed"
    } else if !state.interrupted_node_ids.is_empty() {
        "interrupted"
    } else {
        "passed"
    };
    let mut completion_requirements =
        workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
    if status == "passed" && workflow_completion_has_missing(&completion_requirements) {
        status = "failed";
        state
            .blocked_node_ids
            .extend(completion_requirements.iter().filter_map(|requirement| {
                (requirement.status != "satisfied")
                    .then(|| requirement.node_id.clone())
                    .flatten()
            }));
        state.blocked_node_ids.sort();
        state.blocked_node_ids.dedup();
        completion_requirements =
            workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
    }
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        &mut state,
        &run_id,
        &thread_id,
        None,
        status,
        format!("Workflow run {}.", status),
        &mut checkpoints,
    )?;
    let summary = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread_id.clone()),
        status: status.to_string(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: bundle.workflow.nodes.len(),
        test_count: Some(bundle.tests.len()),
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: if status == "passed" {
            "Workflow completed with durable checkpoints.".to_string()
        } else {
            format!("Workflow {} with structured blockers.", status)
        },
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_completed",
        None,
        Some(status),
        Some(summary.summary.clone()),
        None,
    );
    let mut final_thread = thread.clone();
    final_thread.status = status.to_string();
    final_thread.latest_checkpoint_id = Some(checkpoint_id);
    save_workflow_thread(workflow_path, &final_thread)?;
    let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
        workflow_attach_harness_run_artifacts(&bundle.workflow, &run_id, &mut node_runs);
    let result = workflow_finalize_run_result(
        workflow_path,
        &bundle.workflow,
        WorkflowRunResultParts {
            summary,
            thread: final_thread,
            final_state: state,
            node_runs,
            checkpoints,
            events,
            harness_attempts,
            harness_shadow_comparisons,
            harness_gated_cluster_runs,
            completion_requirements,
            interrupt: None,
        },
    )?;
    Ok(result)
}

pub(super) fn new_workflow_thread(workflow_path: &Path, input: Option<Value>) -> WorkflowThread {
    let created_at_ms = now_ms();
    WorkflowThread {
        id: unique_runtime_id("workflow-thread"),
        workflow_path: workflow_path.display().to_string(),
        status: "queued".to_string(),
        created_at_ms,
        latest_checkpoint_id: None,
        input,
    }
}

pub(super) fn initial_workflow_state(
    thread: &WorkflowThread,
    run_id: &str,
) -> WorkflowStateSnapshot {
    let mut values = std::collections::BTreeMap::new();
    if let Some(input) = thread.input.clone() {
        values.insert("input".to_string(), input);
    }
    WorkflowStateSnapshot {
        thread_id: thread.id.clone(),
        checkpoint_id: "start".to_string(),
        run_id: run_id.to_string(),
        step_index: 0,
        values,
        node_outputs: std::collections::BTreeMap::new(),
        completed_node_ids: Vec::new(),
        blocked_node_ids: Vec::new(),
        interrupted_node_ids: Vec::new(),
        active_node_ids: Vec::new(),
        branch_decisions: std::collections::BTreeMap::new(),
        pending_writes: Vec::new(),
    }
}

pub(super) fn workflow_single_node_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    node_id: &str,
    input: Option<Value>,
    dry_run: bool,
    skill_resolver: &WorkflowSkillResolver,
) -> Result<WorkflowRunResult, String> {
    ensure_workflow_runtime_dirs(workflow_path)?;
    let node = workflow_node_by_id(workflow, node_id)
        .ok_or_else(|| format!("Workflow node '{}' was not found.", node_id))?;
    let started_at_ms = now_ms();
    let run_id = unique_runtime_id(if dry_run {
        "workflow-dry-run"
    } else {
        "workflow-node-run"
    });
    let thread = new_workflow_thread(workflow_path, input.clone());
    save_workflow_thread(workflow_path, &thread)?;
    let mut state = initial_workflow_state(&thread, &run_id);
    let mut events = Vec::new();
    let mut checkpoints = Vec::new();
    let execution_input = input.unwrap_or_else(|| json!({"dryRun": dry_run}));
    let mut node_run = WorkflowNodeRun {
        node_id: node_id.to_string(),
        node_type: workflow_node_type(node),
        status: "running".to_string(),
        started_at_ms,
        finished_at_ms: None,
        attempt: 1,
        input: Some(execution_input.clone()),
        output: None,
        error: None,
        checkpoint_id: None,
        lifecycle: Vec::new(),
        harness_attempt: None,
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread.id,
        "node_started",
        Some(node_id),
        Some("running"),
        Some(format!("{} started.", workflow_node_name(node))),
        None,
    );
    let execution = execute_workflow_node(
        workflow_path,
        Some(workflow),
        node,
        execution_input,
        1,
        None,
        skill_resolver,
    );
    let status = match execution {
        Ok(output) => {
            state
                .node_outputs
                .insert(node_id.to_string(), output.clone());
            state.values.insert(node_id.to_string(), output.clone());
            state.completed_node_ids.push(node_id.to_string());
            state.step_index = 1;
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread.id,
                Some(node_id),
                "passed",
                format!("{} completed.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            node_run.status = "success".to_string();
            node_run.finished_at_ms = Some(now_ms());
            node_run.output = Some(output.clone());
            node_run.checkpoint_id = Some(checkpoint_id);
            node_run.lifecycle = workflow_node_lifecycle_steps("success");
            workflow_push_event(
                &mut events,
                &run_id,
                &thread.id,
                "node_succeeded",
                Some(node_id),
                Some("success"),
                Some(format!("{} completed.", workflow_node_name(node))),
                Some(vec![WorkflowStateUpdate {
                    node_id: node_id.to_string(),
                    key: node_id.to_string(),
                    value: output,
                    reducer: "replace".to_string(),
                }]),
            );
            "passed".to_string()
        }
        Err(error) => {
            state.blocked_node_ids.push(node_id.to_string());
            state.step_index = 1;
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread.id,
                Some(node_id),
                "blocked",
                format!("{} blocked.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            node_run.status = "blocked".to_string();
            node_run.finished_at_ms = Some(now_ms());
            node_run.error = Some(error.clone());
            node_run.checkpoint_id = Some(checkpoint_id);
            node_run.lifecycle = workflow_node_lifecycle_steps("blocked");
            workflow_push_event(
                &mut events,
                &run_id,
                &thread.id,
                "node_blocked",
                Some(node_id),
                Some("blocked"),
                Some(error),
                None,
            );
            "blocked".to_string()
        }
    };
    let summary = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread.id.clone()),
        status: status.clone(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: 1,
        test_count: None,
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: if dry_run {
            format!("Function dry run {}.", status)
        } else {
            format!("Node run {}.", status)
        },
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread.id,
        "run_completed",
        None,
        Some(&status),
        Some(summary.summary.clone()),
        None,
    );
    let mut final_thread = thread.clone();
    final_thread.status = status;
    final_thread.latest_checkpoint_id = checkpoints.last().map(|checkpoint| checkpoint.id.clone());
    save_workflow_thread(workflow_path, &final_thread)?;
    let mut node_runs = vec![node_run];
    let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
        workflow_attach_harness_run_artifacts(workflow, &run_id, &mut node_runs);
    let completion_requirements = workflow_completion_requirements(workflow, &state, &node_runs);
    let result = workflow_finalize_run_result(
        workflow_path,
        workflow,
        WorkflowRunResultParts {
            summary,
            thread: final_thread,
            final_state: state,
            node_runs,
            checkpoints,
            events,
            harness_attempts,
            harness_shadow_comparisons,
            harness_gated_cluster_runs,
            completion_requirements,
            interrupt: None,
        },
    )?;
    append_workflow_evidence(
        workflow_path,
        WorkflowEvidenceSummary {
            id: result.summary.id.clone(),
            kind: if dry_run { "test_run" } else { "run" }.to_string(),
            created_at_ms: result.summary.started_at_ms,
            summary: result.summary.summary.clone(),
            path: Some(
                workflow_run_result_path(workflow_path, &result.summary.id)
                    .display()
                    .to_string(),
            ),
        },
    )?;
    Ok(result)
}
